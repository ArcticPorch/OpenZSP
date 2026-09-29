"""
Tests on the labelled corpus itself, rather than on any code that reads it.

A ground-truth set is a measuring instrument, and an uncalibrated instrument
produces confident nonsense. These tests assert the properties that make a
precision/recall number meaningful: that negative controls exist in quantity,
that every labelled subject actually survives to the domain layer, and -- most
importantly -- that the discriminating pairs really are indistinguishable in
`IdentityFeatures`. If a pair ever stops being feature-identical, it has quietly
stopped testing anything, and the rule it was built to constrain is free to
regress without failing a test.
"""

from collections import Counter
from datetime import datetime, timezone

import pytest

from app.connectors.synthetic import SCENARIOS, SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.features import FeatureExtractor, IdentityFeatures
from app.risk.models import RiskFactorType

ANCHOR = datetime(2026, 9, 9, 0, 0, 0, tzinfo=timezone.utc)

# The smallest corpus on which a single miss moves recall by less than five
# points. Below this, the metric reports sampling noise as detection quality.
MIN_POSITIVE_FINDINGS = 20
MIN_NEGATIVE_CONTROLS = 8


def estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


def features_for(est, identity_id: str) -> IdentityFeatures:
    identity = est.identity(identity_id)
    assert identity is not None, f"{identity_id} missing from the estate"
    return FeatureExtractor.extract_features(identity, est.resources, est.events, ANCHOR)


def findings():
    return SyntheticConnector(anchor_time=ANCHOR).expected_findings()


# --- Corpus integrity ------------------------------------------------------


def test_scenario_names_are_unique():
    names = [s.name for s in SCENARIOS]
    assert len(names) == len(set(names))


def test_corpus_is_large_enough_to_quote_a_metric():
    labels = findings()
    positive = [f for f in labels if f.should_fire]
    negative = [f for f in labels if not f.should_fire]
    assert len(positive) >= MIN_POSITIVE_FINDINGS, (
        f"{len(positive)} positives: one miss moves recall by "
        f"{100 / max(len(positive), 1):.0f} points"
    )
    assert len(negative) >= MIN_NEGATIVE_CONTROLS


def test_negative_controls_are_a_meaningful_share():
    """
    A corpus of positives only measures eagerness.

    A rule that fires unconditionally scores perfect recall on an all-positive
    set. Negative controls are the only thing that makes precision computable.
    """
    labels = findings()
    negative_share = sum(1 for f in labels if not f.should_fire) / len(labels)
    assert 0.2 <= negative_share <= 0.5, negative_share


def test_every_labelled_subject_exists_in_the_estate():
    """Ground truth naming a dropped identity would score as a miss forever."""
    est = estate()
    known = {i.id for i in est.identities}
    for finding in findings():
        assert finding.subject_id in known, finding.subject_id


def test_every_factor_type_is_labelled():
    """No risk factor in the vocabulary may sit unmeasured."""
    labelled = {f.factor_type for f in findings()}
    missing = {t.value for t in RiskFactorType} - labelled
    assert missing == set(), f"unmeasurable factor types: {missing}"


def test_each_factor_type_has_both_polarities():
    """
    A factor with only positive labels cannot have its precision measured.

    No exemptions remain. If you add a factor type, it needs both a positive
    and a negative control before it can be claimed as covered.
    """
    by_type: dict[str, Counter] = {}
    for f in findings():
        by_type.setdefault(f.factor_type, Counter())[f.should_fire] += 1

    for factor, counts in by_type.items():
        assert counts[True] > 0, f"{factor} has no positive label"
        assert counts[False] > 0, f"{factor} has no negative control"


def test_corpus_normalizes_without_issues():
    assert estate().issues == ()


def test_corpus_is_deterministic():
    a = [e.id for e in SyntheticConnector(anchor_time=ANCHOR).collect()]
    b = [e.id for e in SyntheticConnector(anchor_time=ANCHOR).collect()]
    assert a == b


# --- Discriminating pairs --------------------------------------------------
#
# Each of these asserts that two identities are identical where a naive rule
# looks, and differ only in something it ignores.


def test_pair_failed_login_rate_not_count():
    """
    svc_deploy (attack) and marcus (fat fingers) both show 12 failed logins.

    12 inside 40 minutes versus 12 across 30 days. `failed_authentication_count`
    cannot separate them, so a rule keyed on the count is wrong half the time.
    """
    est = estate()
    attacker = features_for(est, "svc_deploy")
    benign = features_for(est, "marcus")

    assert attacker.failed_authentication_count == benign.failed_authentication_count == 12

    # The separation has to come from rate. marcus's failures are spread out,
    # so almost none of them land inside the recent windows.
    assert attacker.recent_event_count_24h > benign.recent_event_count_24h


def test_pair_grant_age_not_usage():
    """
    alice (dormant 420 days) and grace (granted 2 days ago) are feature-identical.

    Same standing count, same privileged count, same critical count, both with
    no privileged use at all. Only `Permission.granted_at` separates them, and
    that is not a feature -- so no threshold over IdentityFeatures can.
    """
    est = estate()
    alice = features_for(est, "alice")
    grace = features_for(est, "grace")

    assert alice.standing_permission_count == grace.standing_permission_count
    assert alice.privileged_permission_count == grace.privileged_permission_count
    assert (
        alice.standing_critical_permission_count
        == grace.standing_critical_permission_count
    )
    assert alice.days_since_last_privileged_use is None
    assert grace.days_since_last_privileged_use is None

    # The discriminator, available on the domain object but not the features.
    alice_grant = est.identity("alice").permissions[0]
    grace_grant = est.identity("grace").permissions[0]
    assert (ANCHOR - alice_grant.granted_at).days > 400
    assert (ANCHOR - grace_grant.granted_at).days < 7


def test_pair_privilege_is_joined_to_sensitivity():
    """
    bob and ines hold the same grant: standing admin, 300 days, used near-daily.

    bob's is over a CRITICAL production cluster, ines's over a MEDIUM staging
    one. Every usage and privilege feature matches; only the critical count
    differs. This is the TRAIN-side trap on the sensitivity line -- henry
    guards it from LOW, but henry is in the holdout.
    """
    est = estate()
    bob = features_for(est, "bob")
    ines = features_for(est, "ines")
    hugo = features_for(est, "hugo")

    for f in (bob, ines, hugo):
        assert f.standing_permission_count == f.privileged_permission_count == 1
        assert f.total_event_count == bob.total_event_count
    assert bob.standing_critical_permission_count == 1
    assert ines.standing_critical_permission_count == 0
    assert hugo.standing_critical_permission_count == 0

    # The rung that differs: hugo's resource is HIGH, ines's MEDIUM.
    sens = {r.id: r.sensitivity.value for r in est.resources}
    assert sens["internal_api_gateway"] == "high"
    assert sens["staging_cluster"] == "medium"


def test_pair_creep_is_the_grant_dates_not_the_grants():
    """
    agent_ops and agent_intake hold the same five grants and use them the same.

    One accumulated them a month at a time; the other received them in one
    afternoon. Only `Permission.granted_at` differs, and it is not a feature.
    """
    est = estate()
    creep = features_for(est, "agent_ops")
    batch = features_for(est, "agent_intake")
    for name in (
        "standing_permission_count",
        "privileged_permission_count",
        "standing_critical_permission_count",
        "total_event_count",
    ):
        assert getattr(creep, name) == getattr(batch, name), name

    creep_dates = {p.granted_at.date() for p in est.identity("agent_ops").permissions}
    batch_dates = {p.granted_at.date() for p in est.identity("agent_intake").permissions}
    assert len(creep_dates) == 5
    assert len(batch_dates) == 1


def test_pair_secret_is_the_resource_type_not_the_capability():
    """otto and pablo: standing READ on a CRITICAL resource, used weekly. Vault vs database."""
    est = estate()
    otto = features_for(est, "otto")
    pablo = features_for(est, "pablo")
    assert otto.standing_critical_permission_count == pablo.standing_critical_permission_count == 1
    assert otto.privileged_permission_count == pablo.privileged_permission_count == 0
    assert otto.total_event_count == pablo.total_event_count

    kinds = {r.id: r.resource_type.value for r in est.resources}
    assert kinds["prod_vault"] == "secret_store"
    assert kinds["orders_db"] == "database"


def test_no_resource_is_shared_between_scenarios():
    """
    The peer baseline is built from each resource's holders. That is only
    split-sound if every resource belongs to exactly one scenario: then adding
    or removing other scenarios cannot change who holds it.
    """
    owners: dict[str, str] = {}
    for scenario in SCENARIOS:
        est = Normalizer().normalize(
            SyntheticConnector(anchor_time=ANCHOR, scenarios=[scenario]).collect()
        )
        for r in est.resources:
            assert owners.setdefault(r.id, scenario.name) == scenario.name, r.id


def test_pair_breadth_needs_weighting():
    """
    svc_ci_runner and iris both hold six standing grants.

    One is admin over production and payments; the other is read over dashboards.
    A blast-radius rule counting grants unweighted scores them identically.
    """
    est = estate()
    sprawl = features_for(est, "svc_ci_runner")
    analyst = features_for(est, "iris")

    assert sprawl.standing_permission_count == analyst.standing_permission_count == 6
    assert sprawl.privileged_permission_count == 6
    assert analyst.privileged_permission_count == 0
    assert sprawl.standing_critical_permission_count == 2
    assert analyst.standing_critical_permission_count == 0


def test_pair_blind_spot_kinds_are_distinct():
    """
    carol and priya are both untrustworthy, for different reasons.

    carol: a connector that stopped (stale collected_at, fresh-looking facts).
    priya: a connector running fine but seeing half the estate (current
    collected_at, completeness 0.5). An engine keyed on collection lag alone
    catches carol and silently trusts priya.
    """
    from app.risk.coverage import CoverageAnalyzer

    est = estate()

    def coverage(identity_id):
        identity = est.identity(identity_id)
        return CoverageAnalyzer.summarize(identity, est.events, est, ANCHOR)

    carol = coverage("carol")
    priya = coverage("priya")

    # carol is caught by lag.
    assert carol.activity_collection_staleness_days == pytest.approx(14.0, abs=0.01)
    # priya is not -- her collection is current.
    assert priya.activity_collection_staleness_days == pytest.approx(0.0, abs=0.01)
    # But her completeness and identity mapping are both degraded.
    assert priya.min_completeness == pytest.approx(0.5)
    assert priya.min_identity_mapping_confidence == pytest.approx(0.6)


def test_negative_control_jit_is_not_stale():
    """
    elena holds a JIT-eligible grant she has never exercised.

    This is a remediated grant -- the product's own success state. It must be
    distinguishable from a dormant standing grant, or the engine penalises
    every successful remediation.
    """
    est = estate()
    elena = features_for(est, "elena")
    assert elena.jit_eligible_permission_count == 1
    assert elena.standing_permission_count == 0
    assert elena.days_since_last_privileged_use is None


def test_negative_control_expired_grant_is_detectable():
    est = estate()
    assert features_for(est, "dmitri").expired_permission_count == 1


def test_pair_exposure_needs_joining_to_sensitivity():
    """
    quentin and rosa both hold standing grants on PUBLIC resources.

    quentin's is admin on a CRITICAL export bucket; rosa's are write on LOW
    marketing pages. A rule firing on exposure alone flags every status page in
    the estate, so exposure is only meaningful joined to sensitivity and action.
    """
    est = estate()
    toxic = features_for(est, "quentin")
    benign = features_for(est, "rosa")

    assert toxic.standing_exposed_permission_count >= 1
    assert benign.standing_exposed_permission_count >= 1

    # The join is what separates them.
    assert toxic.exposed_critical_permission_count == 1
    assert benign.exposed_critical_permission_count == 0
    assert toxic.privileged_exposed_permission_count == 1
    assert benign.privileged_exposed_permission_count == 0


def test_exposure_has_an_identity_side_too():
    """
    partner_integrator's resource is internal; the exposure is the principal.

    Every resource-side feature reads clean here, so a rule looking only at
    Resource.exposure misses third-party access entirely.
    """
    est = estate()
    f = features_for(est, "partner_integrator")
    assert f.exposed_resource_permission_count == 0
    assert est.identity("partner_integrator").is_external is True
    assert est.identity("quentin").is_external is False


def test_pair_context_is_the_attribute_not_the_grant():
    """
    oscar (Marketing) and sonia (Finance) hold the same grant shape.

    Standing admin on a CRITICAL finance database, actively used, in both cases.
    Every feature matches; only `Identity.department` differs. A privilege rule
    must fire on both, a context rule on only one.
    """
    est = estate()
    oscar = features_for(est, "oscar")
    sonia = features_for(est, "sonia")

    assert oscar.standing_permission_count == sonia.standing_permission_count == 1
    assert oscar.privileged_permission_count == sonia.privileged_permission_count == 1
    assert (
        oscar.standing_critical_permission_count
        == sonia.standing_critical_permission_count
        == 1
    )

    assert est.identity("oscar").department == "Marketing"
    assert est.identity("sonia").department == "Finance"
