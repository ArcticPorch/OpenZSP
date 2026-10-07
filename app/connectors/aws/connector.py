"""
AWS account export -> Evidence. A real connector, peer of SyntheticConnector,
reading the JSON an administrator can produce with read-only CLI calls:

    manifest.json              {"account_id": "...", "exported_at": "<ISO-8601>"}
    authorization_details.json aws iam get-account-authorization-details
    scps.json                  [{"level": "root", "policies": [{"PolicyId", "Name", "Content"}]}, ...]
                               (aws organizations list-policies-for-target + describe-policy, per level)
    config_resources.json      aws configservice select-resource-config --expression
                               "SELECT arn, resourceType, tags"   (every resource Config records)
    resources.json             aws resourcegroupstaggingapi get-resources   (tags; tagged resources only)
    resource_policies.json     {"<resource arn>": <policy document>}  (bucket, key, secret policies)
    cloudtrail.json            CloudTrail {"Records": [...]} as delivered to S3

Only `manifest.json` and `authorization_details.json` are required. Nothing is
called live: no credentials in the tool, no dependency, and the same export
always yields the same evidence.

**The resource list is the union of three sources**, because each alone misses
resources and a resource nobody lists is access nobody evaluates -- the
understatement this engine must not make. AWS Config sees everything it
records, tagged or not; the tagging API carries tags but returns only resources
that have (or had) tags; and every exact ARN a policy names is added too, so a
resource referenced in a policy is never invisible even with no inventory file.

Mapping decisions (agreed with the user, 2026-10-05):

* **Policy evaluation lives here**, with the action table: IAM's language is
  AWS's, so the normalizer and rules stay cloud-agnostic. Every effective grant
  names the policies it came from (`derived_from`), and those documents are
  emitted too, so a finding cites "admin, via this policy".
* **Users are identities, roles are both** -- a role identity holding its
  policies, and the role's ARN as a resource pointing at it (`principal_id`).
  Who may become the role is the trust policy plus identity policies.
* **The account's IAM is a control plane.** A pseudo-resource per account
  (`arn:aws:iam::<account>:account-iam`, CRITICAL) governs every resource in
  the export: permission management over IAM is permission management over
  everything identity-based in the account -- except resources an SCP deny
  fences, since IAM cannot grant past an SCP.
* **Sensitivity and exposure**: `zsp:sensitivity` / `zsp:exposure` tags first;
  otherwise secret and key stores are HIGH, IAM and Organizations CRITICAL,
  anything else MEDIUM, and a resource policy granting `"*"` makes it PUBLIC.
  An untagged sensitivity is a guess, so grants on it carry lower completeness.
* **Conditions are never assumed false**: a capability resting only on
  conditional allows is still granted, with its condition keys and lower
  completeness, so confidence falls instead of access disappearing.
* **Identity hints come from tags**: `zsp:identity-type` (human / service /
  ai_agent; users default to human), `zsp:department`, `zsp:org-path`,
  `zsp:break-glass`, `zsp:external`.
* **CloudTrail**: ConsoleLogin is an INTERACTIVE login; AssumeRole is an
  assume_role by the caller on the role; every other call is mapped through the
  action table to read / write / delete / grant / revoke on the resource it
  names. Calls made with a long-term access key (AKIA...) are PROGRAMMATIC.
  A call made through a role session is attributed to the user named by the
  session's `sourceIdentity` when there is one -- a role's activity belongs to
  whoever assumed it -- and to the role otherwise.
"""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from app.common.validation import validate_tz_datetime
from app.connectors.aws.actions import capability_of_action
from app.connectors.aws.policy import (
    Statement,
    effective_capabilities,
    fenced_by_scp,
    is_public,
    parse_policy,
    service_of,
)
from app.evidence.models import (
    Evidence,
    EvidenceQuality,
    RecordKind,
    SourceRef,
    SourceType,
    content_id,
)
from app.models.capability import Capability

SNAPSHOT_QUALITY = EvidenceQuality(
    source_reliability=0.95, integrity_authenticity=1.0,
    identity_mapping_confidence=1.0, completeness=1.0,
)
# A grant whose target's sensitivity is a service default, not a tag.
UNTAGGED_COMPLETENESS = 0.8
# A grant resting only on conditional allows.
CONDITIONAL_COMPLETENESS = 0.6

_DEFAULT_SENSITIVITY = {
    "secretsmanager": "high", "kms": "high", "ssm": "medium",
    "iam": "critical", "organizations": "critical",
}
_RESOURCE_TYPE = {
    "s3": "database", "dynamodb": "database", "rds": "database", "redshift": "database",
    "secretsmanager": "secret_store", "kms": "secret_store",
    "lambda": "server", "ec2": "server", "ecs": "server", "eks": "server",
    "codecommit": "repository", "ecr": "repository",
    "apigateway": "api", "execute-api": "api",
}
_EVENT_ACTION = {
    Capability.READ: "read", Capability.AUTHENTICATE: "login",
    Capability.WRITE: "write", Capability.DEPLOY: "write",
    Capability.MANAGE_IDENTITY: "write", Capability.MANAGE_SECURITY_CONTROL: "write",
    Capability.DESTROY: "delete", Capability.IMPERSONATE: "assume_role",
    Capability.ADMIN: "write", Capability.UNKNOWN: "write",
}


def _load(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _tags(raw) -> dict[str, str]:
    """
    AWS tags arrive as [{"Key","Value"}] (IAM, tagging API) or [{"key","value"}]
    (AWS Config); accept a plain dict too.
    """
    if isinstance(raw, dict):
        return {str(k).lower(): str(v) for k, v in raw.items()}
    return {
        str(t.get("Key", t.get("key", ""))).lower(): str(t.get("Value", t.get("value", "")))
        for t in raw or ()
    }


def _referenced_arns(statements, account_id: str) -> set[str]:
    """
    Exact resource ARNs named in policies, in this account (or account-less,
    like S3). `bucket/*` names the bucket. IAM ARNs are principals and
    policies, not resources, and are left out; wildcards name no one resource.
    """
    out: set[str] = set()
    for s in statements:
        for pattern in s.resources or ():
            if not pattern.startswith("arn:aws:") or service_of(pattern) in ("iam", "sts", ""):
                continue
            if service_of(pattern) == "s3" and pattern.endswith("/*") and "*" not in pattern[:-2]:
                pattern = pattern[:-2]
            if "*" in pattern or "?" in pattern:
                continue
            account = pattern.split(":")[4]
            if account in ("", account_id):
                out.add(pattern)
    return out


def _document(raw) -> dict:
    """Policy documents may arrive decoded or as a JSON string (SCP Content)."""
    return json.loads(raw) if isinstance(raw, str) else (raw or {})


_ARN = re.compile(r"arn:aws:([a-z0-9-]+):([a-z0-9-]*):(\d*):([^\s,()]+)")


def short_arn(arn: str) -> str:
    """
    A readable label for display only: `user/alice`, `role/SupportRole`,
    `dynamodb:table/customers`, `s3:acme-payments-ledger`. Ids stay full ARNs.
    """
    match = _ARN.fullmatch(arn)
    if match is None:
        return arn
    service, _, _, rest = match.groups()
    return rest if service == "iam" else f"{service}:{rest}"


def shorten_arns(text: str) -> str:
    """Every ARN in free text (a finding's description) to its short label."""
    return _ARN.sub(lambda m: short_arn(m.group(0)), text)


def _short_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class AWSExportConnector:
    """Satisfies EvidenceConnector structurally, like SyntheticConnector."""

    def __init__(self, export_dir) -> None:
        self.root = Path(export_dir)
        manifest = _load(self.root / "manifest.json")
        if manifest is None:
            raise FileNotFoundError(f"{self.root / 'manifest.json'} is required")
        self.account_id = str(manifest["account_id"])
        self.exported_at = datetime.fromisoformat(manifest["exported_at"])
        validate_tz_datetime(self.exported_at, "exported_at")
        self.account_root = f"arn:aws:iam::{self.account_id}:root"
        self.iam_plane = f"arn:aws:iam::{self.account_id}:account-iam"
        self._snapshot = SourceRef(SourceType.AWS_IAM_SNAPSHOT, f"aws:{self.account_id}")
        self._trail = SourceRef(SourceType.AWS_CLOUDTRAIL, f"aws:{self.account_id}")

    def source_ref(self) -> SourceRef:
        return self._snapshot

    # -- evidence construction ------------------------------------------------

    def _evidence(self, kind: RecordKind, refs: dict, payload: dict, *,
                  observed_at: Optional[datetime] = None, source: Optional[SourceRef] = None,
                  completeness: float = 1.0) -> Evidence:
        source = source or self._snapshot
        observed_at = observed_at or self.exported_at
        ref_tuple = tuple(sorted(refs.items()))
        payload_tuple = tuple(sorted(payload.items()))
        quality = SNAPSHOT_QUALITY if completeness == 1.0 else EvidenceQuality(
            source_reliability=0.95, integrity_authenticity=1.0,
            identity_mapping_confidence=1.0, completeness=completeness,
        )
        return Evidence(
            id=content_id(source, kind, observed_at, ref_tuple, payload_tuple),
            source=source, record_kind=kind, observed_at=observed_at,
            collected_at=self.exported_at, quality=quality,
            entity_references=ref_tuple, payload=payload_tuple,
        )

    # -- the export -------------------------------------------------------------

    def collect(self) -> Iterator[Evidence]:
        details = _load(self.root / "authorization_details.json", {}) or {}
        managed = {
            p["Arn"]: next((v["Document"] for v in p.get("PolicyVersionList", ())
                            if v.get("IsDefaultVersion")), {})
            for p in details.get("Policies", ())
        }
        scp_levels = []
        for level in _load(self.root / "scps.json", []) or []:
            statements = []
            for pol in level.get("policies", ()):
                pid = f"scp/{pol.get('PolicyId', pol.get('Name'))}"
                doc = _document(pol.get("Content"))
                statements += parse_policy(doc, pid)
                yield self._policy(pid, doc, "scp")
            scp_levels.append(tuple(statements))

        for arn, doc in managed.items():
            yield self._policy(arn, doc, "managed")

        groups = {g["GroupName"]: g for g in details.get("GroupDetailList", ())}
        resource_policies = {
            arn: _document(doc) for arn, doc in (_load(self.root / "resource_policies.json", {}) or {}).items()
        }

        # Principals' statements first: the policies name resources too.
        roles = details.get("RoleDetailList", ())
        principals = []
        for user in details.get("UserDetailList", ()):
            statements = []
            for name in user.get("GroupList", ()):
                group = groups.get(name, {})
                statements += self._identity_statements(group.get("Arn", name), group, managed)
                yield from self._inline_policies(group.get("Arn", name), group.get("GroupPolicyList", ()))
            statements += self._identity_statements(user["Arn"], user, managed)
            yield from self._inline_policies(user["Arn"], user.get("UserPolicyList", ()))
            principals.append((user, statements, "user"))
        for role in roles:
            statements = self._identity_statements(role["Arn"], role, managed)
            yield from self._inline_policies(role["Arn"], role.get("RolePolicyList", ()))
            principals.append((role, statements, "role"))

        # Resources: Config's inventory, the tagging API's tags, every exact ARN
        # a policy names, every role's ARN, and the IAM plane.
        resources: dict[str, dict] = {}

        def add(arn: str, tags: dict) -> None:
            entry = resources.setdefault(arn, {"tags": {}, "principal": None})
            entry["tags"].update(tags)

        for row in (_load(self.root / "config_resources.json", {}) or {}).get("Results", ()):
            item = json.loads(row) if isinstance(row, str) else row
            if item.get("arn"):
                add(item["arn"], _tags(item.get("tags")))
        for item in (_load(self.root / "resources.json", {}) or {}).get("ResourceTagMappingList", ()):
            add(item["ResourceARN"], _tags(item.get("Tags")))
        all_statements = [s for _, stmts, _ in principals for s in stmts]
        for arn in sorted(_referenced_arns(all_statements, self.account_id)):
            add(arn, {})
        for arn in resource_policies:
            add(arn, {})
        for role in roles:
            resources[role["Arn"]] = {"tags": _tags(role.get("Tags")), "principal": role["Arn"]}

        resource_statements: dict[str, tuple[Statement, ...]] = {}
        for arn, doc in resource_policies.items():
            pid = f"{arn}#resource-policy"
            resource_statements[arn] = parse_policy(doc, pid)
            yield self._policy(pid, doc, "resource")
        for role in roles:
            pid = f"{role['Arn']}#trust"
            doc = _document(role.get("AssumeRolePolicyDocument"))
            resource_statements[role["Arn"]] = parse_policy(doc, pid)
            yield self._policy(pid, doc, "trust")

        untagged: set[str] = set()
        for arn, info in sorted(resources.items()):
            yield self._resource(arn, info, resource_statements.get(arn, ()), untagged)
        governed = tuple(sorted(a for a in resources if not fenced_by_scp(a, scp_levels)))
        yield self._evidence(RecordKind.RESOURCE, {"resource_id": self.iam_plane}, {
            "name": f"IAM (account {self.account_id})", "resource_type": "cloud_account",
            "sensitivity": "critical", "governs": governed,
        })

        # Principals and their effective grants.
        targets = sorted(resources) + [self.iam_plane]
        for principal, statements, kind in principals:
            yield self._identity(principal, kind)
            boundary_arn = (principal.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
            boundary = parse_policy(managed.get(boundary_arn, {}), boundary_arn) if boundary_arn else None
            for target in targets:
                for eff in effective_capabilities(
                    principal["Arn"], target, statements,
                    resource_statements=resource_statements.get(target, ()),
                    boundary=boundary, scp_levels=scp_levels, account_root=self.account_root,
                ):
                    yield self._grant(principal["Arn"], target, eff, target in untagged)

        self._users_by_name = {
            u["UserName"]: u["Arn"] for u in details.get("UserDetailList", ())
        }
        yield from self._cloudtrail()

    # -- pieces -------------------------------------------------------------------

    def _policy(self, policy_id: str, document: dict, kind: str) -> Evidence:
        return self._evidence(RecordKind.POLICY_DOCUMENT, {"policy_id": policy_id},
                              {"kind": kind, "document": json.dumps(document, sort_keys=True)})

    def _inline_policies(self, owner_arn: str, inline) -> Iterator[Evidence]:
        for pol in inline:
            yield self._policy(f"{owner_arn}#inline/{pol['PolicyName']}",
                               _document(pol.get("PolicyDocument")), "inline")

    def _identity_statements(self, owner_arn: str, entry: dict, managed: dict) -> list[Statement]:
        out: list[Statement] = []
        for att in entry.get("AttachedManagedPolicies", ()):
            out += parse_policy(managed.get(att["PolicyArn"], {}), att["PolicyArn"])
        inline = [*entry.get("UserPolicyList", ()), *entry.get("RolePolicyList", ()),
                  *entry.get("GroupPolicyList", ())]
        for pol in inline:
            out += parse_policy(_document(pol.get("PolicyDocument")),
                                f"{owner_arn}#inline/{pol['PolicyName']}")
        return out

    def _identity(self, principal: dict, kind: str) -> Evidence:
        tags = _tags(principal.get("Tags"))
        identity_type = "role" if kind == "role" else tags.get("zsp:identity-type", "human")
        payload = {
            "name": principal.get("UserName") or principal.get("RoleName"),
            "identity_type": identity_type,
            "department": tags.get("zsp:department", "Unassigned"),
        }
        if tags.get("zsp:org-path"):
            payload["org_path"] = tags["zsp:org-path"]
        if tags.get("zsp:break-glass", "").lower() == "true":
            payload["is_break_glass"] = True
        if tags.get("zsp:external", "").lower() == "true":
            payload["is_external"] = True
        return self._evidence(RecordKind.IDENTITY, {"identity_id": principal["Arn"]}, payload)

    def _resource(self, arn: str, info: dict, statements, untagged: set) -> Evidence:
        tags, service = info["tags"], service_of(arn)
        sensitivity = tags.get("zsp:sensitivity")
        if sensitivity is None:
            # A role's ARN is a stepping-stone into the role, not the IAM
            # control plane: its reach is counted through the role's grants.
            sensitivity = "medium" if info["principal"] else _DEFAULT_SENSITIVITY.get(service, "medium")
            untagged.add(arn)
        exposure = tags.get("zsp:exposure") or ("public" if is_public(statements) else "internal")
        payload = {
            "name": tags.get("name") or arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1] or arn,
            "resource_type": "cloud_account" if info["principal"] else _RESOURCE_TYPE.get(service, "cloud_account"),
            "sensitivity": sensitivity.lower(),
            "exposure": exposure.lower(),
        }
        if info["principal"]:
            payload["principal_id"] = info["principal"]
        return self._evidence(RecordKind.RESOURCE, {"resource_id": arn}, payload)

    def _grant(self, principal_arn: str, resource_arn: str, eff, untagged: bool) -> Evidence:
        grant_id = f"aws-grant-{_short_id(principal_arn, resource_arn, eff.capability.value)}"
        payload = {
            "grant_id": grant_id, "action": eff.capability.value, "lifecycle": "standing",
            "derived_from": eff.sources,
        }
        completeness = 1.0
        if eff.conditional:
            payload["conditions"] = eff.condition_keys
            completeness = CONDITIONAL_COMPLETENESS
        if untagged:
            completeness = min(completeness, UNTAGGED_COMPLETENESS)
        return self._evidence(
            RecordKind.PERMISSION_GRANT,
            {"identity_id": principal_arn, "resource_id": resource_arn, "grant_id": grant_id},
            payload, completeness=completeness,
        )

    def _cloudtrail(self) -> Iterator[Evidence]:
        trail = _load(self.root / "cloudtrail.json", {}) or {}
        for record in trail.get("Records", ()):
            mapped = self._event(record)
            if mapped is not None:
                yield mapped

    def _event(self, record: dict) -> Optional[Evidence]:
        who = record.get("userIdentity", {})
        actor = who.get("arn", "")
        if who.get("type") == "AssumedRole":
            session = who.get("sessionContext", {})
            source = session.get("sourceIdentity") or record.get("sourceIdentity")
            actor = getattr(self, "_users_by_name", {}).get(source)                 or session.get("sessionIssuer", {}).get("arn", actor)
        if not actor:
            return None
        name = record.get("eventName", "")
        service = record.get("eventSource", "").split(".", 1)[0]
        success = "errorCode" not in record
        auth = "programmatic" if str(who.get("accessKeyId", "")).startswith("AKIA") else "unknown"
        resources = [r.get("ARN") for r in record.get("resources", ()) if r.get("ARN")]
        params = record.get("requestParameters") or {}

        if name == "ConsoleLogin":
            action, auth = "login", "interactive"
            success = (record.get("responseElements") or {}).get("ConsoleLogin") == "Success"
            target = self.iam_plane
        elif name.startswith("AssumeRole"):
            action = "assume_role"
            target = params.get("roleArn") or (resources[0] if resources else self.iam_plane)
        else:
            capability = capability_of_action(f"{service}:{name}")
            if capability is Capability.MANAGE_PERMISSION:
                action = "revoke_permission" if name.lower().startswith(("detach", "delete", "remove")) \
                    else "grant_permission"
            else:
                action = _EVENT_ACTION.get(capability, "write")
            if resources:
                target = resources[0]
            elif service == "s3" and params.get("bucketName"):
                target = f"arn:aws:s3:::{params['bucketName']}"
            elif service in ("iam", "sts"):
                target = self.iam_plane
            else:
                target = f"arn:aws:{service}:{record.get('awsRegion', '')}:{self.account_id}:unspecified"

        event_id = record.get("eventID") or _short_id(actor, name, record.get("eventTime", ""))
        observed = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        return self._evidence(
            RecordKind.ACTIVITY_EVENT,
            {"identity_id": actor, "resource_id": target, "event_id": event_id},
            {"event_id": event_id, "action": action, "success": success, "auth": auth,
             "aws_event": f"{service}:{name}"},
            observed_at=observed, source=self._trail,
        )
