"""
The AWS connector end to end, on examples/aws_sample_account: a CLI-shaped
export through effective-permission evaluation, the normalizer, the graph and
the rules. Each planted situation is real IAM mechanics the engine must find.
"""

from pathlib import Path

import pytest

from app.connectors.aws.connector import AWSExportConnector
from app.evidence.models import RecordKind
from app.models.capability import Capability as C
from app.models.event import AuthKind
from app.models.resource import Exposure, Sensitivity
from app.normalize.normalizer import Normalizer
from app.risk.engine import RiskEngine

SAMPLE = Path(__file__).resolve().parent.parent / "examples" / "aws_sample_account"
ACCOUNT = "111122223333"


def user(name):
    return f"arn:aws:iam::{ACCOUNT}:user/{name}"


@pytest.fixture(scope="module")
def connector():
    return AWSExportConnector(SAMPLE)


@pytest.fixture(scope="module")
def estate(connector):
    return Normalizer().normalize(connector.collect())


@pytest.fixture(scope="module")
def findings(estate, connector):
    out = {}
    for r in RiskEngine().assess_estate(estate, connector.exported_at):
        out[r.identity_id.rsplit("/", 1)[-1]] = {
            f.factor_type.value: f for f in r.assessment.triggered_factors
        }
    return out


def caps(estate, who, resource_fragment):
    return {p.action for p in estate.identity(user(who)).permissions if resource_fragment in p.resource_id}


# --- Ingestion ---------------------------------------------------------------


def test_the_export_normalizes_cleanly(estate):
    assert estate.issues == ()
    assert len(estate.identities) == 11  # 8 users + 3 roles
    assert len(estate.events) == 416


def test_collection_is_deterministic(connector):
    assert [e.id for e in connector.collect()] == [e.id for e in AWSExportConnector(SAMPLE).collect()]


def test_roles_are_principals_behind_their_arns(estate):
    role = f"arn:aws:iam::{ACCOUNT}:role/DataEngineerRole"
    assert estate.resource(role).principal_id == role
    assert estate.identity(role).identity_type.value == "role"


def test_the_iam_control_plane_governs_the_account(estate):
    plane = estate.resource(f"arn:aws:iam::{ACCOUNT}:account-iam")
    assert plane.sensitivity is Sensitivity.CRITICAL
    assert "arn:aws:s3:::acme-payments-ledger" in plane.governs


def test_tags_then_service_defaults_set_sensitivity_and_exposure(estate):
    assert estate.resource("arn:aws:s3:::acme-payments-ledger").sensitivity is Sensitivity.CRITICAL
    secret = next(r for r in estate.resources if "prod/db-password" in r.id)
    assert secret.sensitivity is Sensitivity.HIGH  # untagged secret: service default
    assert estate.resource("arn:aws:s3:::acme-marketing-assets").exposure is Exposure.PUBLIC


# --- Effective permissions -----------------------------------------------------


def test_administrator_access_is_admin_not_its_components(estate):
    assert caps(estate, "ci-deployer", "acme-payments-ledger") == {C.ADMIN}


def test_the_boundary_caps_bob(estate):
    plane = caps(estate, "bob", "account-iam")
    assert C.ADMIN not in plane and C.MANAGE_PERMISSION not in plane


def test_the_scp_strips_audit_trail_tampering_even_from_admins(estate):
    for who in ("bob", "ci-deployer"):
        trail = caps(estate, who, "trail/org-trail")
        assert C.MANAGE_SECURITY_CONTROL not in trail and C.ADMIN not in trail


def test_a_public_bucket_is_exposure_not_everyones_grant(estate):
    assert caps(estate, "alice", "acme-marketing-assets") == set()


def test_a_service_only_role_is_not_assumable_by_people(estate):
    assert caps(estate, "alice", "role/LambdaExecRole") == set()
    assert caps(estate, "eve", "role/LambdaExecRole") == set()


def test_a_conditional_grant_is_kept_at_lower_completeness(estate):
    [grant] = estate.identity(user("carol")).permissions
    evidence = estate.evidence_for(RecordKind.PERMISSION_GRANT, grant.id)[0]
    assert grant.action is C.ADMIN
    assert evidence.quality.completeness < 1.0
    assert ("conditions", ("aws:MultiFactorAuthPresent",)) in evidence.payload or \
        dict(evidence.payload)["conditions"] in (("aws:MultiFactorAuthPresent",), ["aws:MultiFactorAuthPresent"])


def test_grants_cite_the_policies_they_came_from(estate):
    [grant] = [p for p in estate.identity(user("alice")).permissions if "DataEngineerRole" in p.resource_id]
    kinds = [e.record_kind for e in estate.evidence_for(RecordKind.PERMISSION_GRANT, grant.id)]
    assert kinds[0] is RecordKind.PERMISSION_GRANT and RecordKind.POLICY_DOCUMENT in kinds


# --- CloudTrail -------------------------------------------------------------------


def test_console_logins_are_interactive_and_key_calls_programmatic(estate):
    deployer = [e for e in estate.events if e.identity_id == user("ci-deployer")]
    assert {e.auth for e in deployer if e.action.value == "login"} == {AuthKind.INTERACTIVE}
    assert {e.auth for e in deployer if e.action.value == "write"} == {AuthKind.PROGRAMMATIC}


def test_role_session_activity_belongs_to_the_assumer(estate):
    scans = [e for e in estate.events if "table/customers" in e.resource_id]
    assert len(scans) == 120 and {e.identity_id for e in scans} == {user("eve")}


# --- What the engine finds -----------------------------------------------------------


def test_the_planted_situations_are_found(findings):
    assert {"EXCESSIVE_PRIVILEGE", "EXCESSIVE_BLAST_RADIUS", "CONTEXT_MISMATCH"} <= set(findings["ci-deployer"])
    assert "PRIVILEGE_ESCALATION" in findings["alice"]
    assert {"MULTI_STAGE_SEQUENCE", "ANOMALOUS_BEHAVIOR"} <= set(findings["eve"])
    assert "EXCESSIVE_PRIVILEGE" in findings["svc-reporting"]
    assert "STALE_ACCESS" in findings["old-intern"]
    assert "EXCESSIVE_PRIVILEGE" in findings["breakglass"] and "STALE_ACCESS" not in findings["breakglass"]


def test_alices_path_is_spelled_out(findings):
    path = findings["alice"]["PRIVILEGE_ESCALATION"].description
    assert "-impersonate->" in path and "=becomes=>" in path and "acme-payments-ledger" in path


def test_the_boundary_keeps_bob_out_of_the_privilege_findings(findings):
    assert "EXCESSIVE_PRIVILEGE" not in findings.get("bob", {})


def test_a_conditional_grant_lowers_confidence(findings):
    assert findings["carol"]["EXCESSIVE_PRIVILEGE"].confidence < findings["ci-deployer"]["EXCESSIVE_PRIVILEGE"].confidence


def test_iam_cannot_grant_past_an_scp(estate, findings):
    """The trail is fenced by an SCP deny, so the IAM plane does not govern it."""
    plane = estate.resource(f"arn:aws:iam::{ACCOUNT}:account-iam")
    assert not any("org-trail" in g for g in plane.governs)
    assert "PRIVILEGE_ESCALATION" not in findings["ci-deployer"]
    assert "PRIVILEGE_ESCALATION" not in findings["breakglass"]


# --- The resource list -------------------------------------------------------------


def test_an_untagged_resource_comes_from_aws_config(estate):
    """The tagging API only returns tagged resources; Config sees the rest."""
    backups = estate.resource("arn:aws:s3:::acme-db-backups")
    assert backups is not None and backups.sensitivity is Sensitivity.MEDIUM  # untagged default
    assert C.ADMIN in caps(estate, "ci-deployer", "acme-db-backups")


def test_a_resource_named_only_in_a_policy_is_still_evaluated(estate):
    table = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/analytics-events"
    assert estate.resource(table) is not None
    assert caps(estate, "alice", "table/analytics-events") == {C.READ}
