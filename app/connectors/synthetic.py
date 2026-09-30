"""
Scenario-driven synthetic evidence.

This is a first-class connector, not a stub. It satisfies the same
EvidenceConnector protocol an AWS reader will, so the engine cannot tell the
difference -- which is what lets the entire pipeline be exercised end to end,
deterministically, before a single cloud credential exists.

Why scenarios rather than random data
-------------------------------------
Random identities with random permissions can tell you the engine does not
crash. They cannot tell you it is *correct*, because nobody knows what the right
answer was. A scenario carries its own ground truth: it plants a specific
situation and declares which findings ought to come out. That turns the
generator into a labelled test set -- you can measure detection, and a rule that
silently stops firing becomes a failing test rather than a quiet regression.

The cost is honest: scenarios only contain what you thought to plant. They will
not surprise you the way fuzzing would. The random filler below exists for
volume and for shaking out crashes, not for correctness.

Negative controls are deliberately included. A rule that fires on every admin is
worthless; `active_admin_justified` exists so that "did not fire" is also a
tested outcome.

Determinism
-----------
No datetime.now() and no unseeded randomness anywhere. Time comes from an
explicit `anchor_time` and randomness from a seeded Random. Two runs with the
same seed and anchor produce byte-identical evidence ids, so assessments are
reproducible and diffable.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import random
from typing import Any, Callable, Iterator, Optional, Sequence

from app.common.validation import validate_non_empty_str, validate_tz_datetime
from app.evidence.models import (
    Evidence,
    EvidenceQuality,
    RecordKind,
    SourceRef,
    SourceType,
    content_id,
)


# Synthetic data is fabricated but internally consistent: we know exactly what we
# wrote, so mapping and integrity are perfect. Reliability is set just below 1.0
# as a standing reminder that this is not ground truth about a real estate.
DEFAULT_QUALITY = EvidenceQuality(
    source_reliability=0.95,
    integrity_authenticity=1.0,
    identity_mapping_confidence=1.0,
    completeness=1.0,
)


@dataclass(frozen=True)
class ExpectedFinding:
    """
    Ground truth for a scenario: what the engine ought to conclude.

    `factor_type` is a plain string rather than a RiskFactorType so that the
    ingestion layer does not import the risk layer. The tests assert that every
    value here is a real RiskFactorType, which recovers the safety of the enum
    without the dependency.

    `should_fire=False` marks a negative control -- an assertion that this factor
    must NOT be raised for this subject.
    """

    factor_type: str
    subject_id: str
    rationale: str
    should_fire: bool = True

    def __post_init__(self) -> None:
        validate_non_empty_str(self.factor_type, "factor_type")
        validate_non_empty_str(self.subject_id, "subject_id")
        validate_non_empty_str(self.rationale, "rationale")


TRAIN = "train"
HOLDOUT = "holdout"
# Scenarios written *after* the rules they are scored against were frozen,
# without reference to any threshold. HOLDOUT predates the split and was
# visible while the rules were written, so it is contaminated; FRESH is the
# only column whose number estimates generalisation. It is read once per
# calibration cycle -- after a reading, it is spent, and the next cycle needs
# new FRESH scenarios.
FRESH = "fresh"
SPLITS = (TRAIN, HOLDOUT, FRESH)


@dataclass(frozen=True)
class Scenario:
    """
    One labelled situation, and which half of the corpus it belongs to.

    `split` exists so that thresholds can be tuned against one set of scenarios
    and reported against another the tuner never opened. Without it, every
    number this project produces is training-set performance -- rules written
    while looking at the answers, which measures memorisation rather than
    detection.

    The split is a property of the scenario rather than a runtime shuffle on
    purpose: a random split would move each run, so a metric could improve
    purely because the seed changed, and nobody could reproduce yesterday's
    number. Membership is fixed, declared, and reviewable in a diff.
    """

    name: str
    description: str
    expected: tuple[ExpectedFinding, ...]
    build: Callable[["EvidenceBuilder", random.Random], list[Evidence]]
    split: str = TRAIN

    def __post_init__(self) -> None:
        validate_non_empty_str(self.name, "name")
        if self.split not in SPLITS:
            raise ValueError(f"split must be one of {SPLITS}, got {self.split!r}")


class EvidenceBuilder:
    """
    Small factory that keeps scenarios readable.

    Every emitted record gets a content-addressed id, so rebuilding an unchanged
    scenario yields identical ids and downstream dedup is exercised for free.
    """

    def __init__(
        self,
        source: SourceRef,
        anchor_time: datetime,
        quality: EvidenceQuality = DEFAULT_QUALITY,
    ) -> None:
        self.source = source
        self.anchor_time = anchor_time
        self.quality = quality

    # -- internals -------------------------------------------------------

    def _make(
        self,
        kind: RecordKind,
        observed_at: datetime,
        refs: dict[str, str],
        payload: dict[str, Any],
        *,
        collected_at: Optional[datetime] = None,
        quality: Optional[EvidenceQuality] = None,
    ) -> Evidence:
        ref_tuple = tuple(sorted(refs.items()))
        payload_tuple = tuple(sorted(payload.items()))
        return Evidence(
            id=content_id(self.source, kind, observed_at, ref_tuple, payload_tuple),
            source=self.source,
            record_kind=kind,
            observed_at=observed_at,
            # Default: collection happens at the anchor, i.e. a healthy connector
            # that has just run. Scenarios override this to simulate lag.
            collected_at=collected_at if collected_at is not None else self.anchor_time,
            quality=quality if quality is not None else self.quality,
            entity_references=ref_tuple,
            payload=payload_tuple,
        )

    def ago(self, **kwargs: float) -> datetime:
        """Time relative to the anchor. Scenarios never reference wall-clock now."""
        return self.anchor_time - timedelta(**kwargs)

    # -- record kinds ----------------------------------------------------

    def identity(
        self,
        identity_id: str,
        name: str,
        identity_type: str,
        department: str,
        *,
        observed_at: Optional[datetime] = None,
        **extra: Any,
    ) -> Evidence:
        return self._make(
            RecordKind.IDENTITY,
            observed_at or self.ago(days=1),
            {"identity_id": identity_id},
            {
                "name": name,
                "identity_type": identity_type,
                "department": department,
                **extra,
            },
        )

    def resource(
        self,
        resource_id: str,
        name: str,
        resource_type: str,
        sensitivity: str,
        *,
        observed_at: Optional[datetime] = None,
        **extra: Any,
    ) -> Evidence:
        return self._make(
            RecordKind.RESOURCE,
            observed_at or self.ago(days=1),
            {"resource_id": resource_id},
            {
                "name": name,
                "resource_type": resource_type,
                "sensitivity": sensitivity,
                **extra,
            },
        )

    def grant(
        self,
        grant_id: str,
        identity_id: str,
        resource_id: str,
        action: str,
        *,
        lifecycle: str = "standing",
        granted_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        observed_at: Optional[datetime] = None,
        collected_at: Optional[datetime] = None,
        quality: Optional[EvidenceQuality] = None,
        **extra: Any,
    ) -> Evidence:
        """
        An effective permission grant.

        `lifecycle` is richer than the current domain model's `standing: bool`
        -- "standing" / "time_bound" / "jit_eligible" / "elevated". The evidence
        layer is allowed to carry more than the domain model understands; the
        normalizer collapses it. That asymmetry is deliberate: it means upgrading
        the domain model later does not require re-ingesting anything.
        """
        payload: dict[str, Any] = {
            "grant_id": grant_id,
            "action": action,
            "lifecycle": lifecycle,
            **extra,
        }
        if granted_at is not None:
            payload["granted_at"] = granted_at.isoformat()
        if expires_at is not None:
            payload["expires_at"] = expires_at.isoformat()

        return self._make(
            RecordKind.PERMISSION_GRANT,
            observed_at or self.ago(days=1),
            {"identity_id": identity_id, "resource_id": resource_id, "grant_id": grant_id},
            payload,
            collected_at=collected_at,
            quality=quality,
        )

    def event(
        self,
        event_id: str,
        identity_id: str,
        resource_id: str,
        action: str,
        observed_at: datetime,
        success: bool = True,
        *,
        collected_at: Optional[datetime] = None,
        quality: Optional[EvidenceQuality] = None,
        **extra: Any,
    ) -> Evidence:
        return self._make(
            RecordKind.ACTIVITY_EVENT,
            observed_at,
            {"identity_id": identity_id, "resource_id": resource_id, "event_id": event_id},
            {"event_id": event_id, "action": action, "success": success, **extra},
            collected_at=collected_at,
            quality=quality,
        )


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


def _dormant_standing_admin(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """The canonical ZSP finding: standing admin on a crown-jewel, never exercised."""
    out = [
        b.identity("alice", "Alice Chen", "human", "Platform Engineering"),
        b.resource("prod_payments_db", "Production Payments DB", "database", "critical"),
        b.grant(
            "g_alice_admin",
            "alice",
            "prod_payments_db",
            "admin",
            lifecycle="standing",
            granted_at=b.ago(days=420),
        ),
    ]
    # She is active -- just never on this grant. An identity-level "last activity"
    # timestamp would call her healthy and miss the dormant grant entirely.
    for day in range(0, 30, 3):
        out.append(
            b.event(
                f"e_alice_read_{day}",
                "alice",
                "internal_wiki",
                "read",
                b.ago(days=day),
            )
        )
    out.append(b.resource("internal_wiki", "Internal Wiki", "api", "low"))
    return out


def _active_admin_justified(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Negative control: standing admin that is genuinely, continuously used."""
    out = [
        b.identity("bob", "Bob Ilori", "human", "Site Reliability"),
        b.resource("prod_cluster", "Production Cluster", "server", "critical"),
        b.grant(
            "g_bob_admin",
            "bob",
            "prod_cluster",
            "admin",
            lifecycle="standing",
            granted_at=b.ago(days=300),
        ),
    ]
    for day in range(0, 21):
        out.append(
            b.event(
                f"e_bob_admin_{day}",
                "bob",
                "prod_cluster",
                "assume_role",
                b.ago(days=day, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _admin_on_medium_internal_tool(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: bob's exact grant shape, one sensitivity band too low to matter.

    Standing admin, 300 days old, exercised near-daily -- identical to bob in
    every respect except that the resource is MEDIUM rather than CRITICAL.
    Loosening `standing_privilege_on_high_value` to fire on MEDIUM-or-above
    fails a TRAIN label instead of passing silently. `henry` guards the same
    axis from further below (LOW) and lives in the holdout, which is where a
    tuning trap must not be.

    With `hugo` (HIGH, must fire) directly above it, the sensitivity line is
    pinned from both sides in TRAIN: bob CRITICAL fires, hugo HIGH fires, ines
    MEDIUM does not.
    """
    out = [
        b.identity("ines", "Ines Carvalho", "human", "Site Reliability"),
        b.resource("staging_cluster", "Staging Cluster", "server", "medium"),
        b.grant(
            "g_ines_admin",
            "ines",
            "staging_cluster",
            "admin",
            lifecycle="standing",
            granted_at=b.ago(days=300),
        ),
    ]
    for day in range(0, 21):
        out.append(
            b.event(
                f"e_ines_admin_{day}",
                "ines",
                "staging_cluster",
                "assume_role",
                b.ago(days=day, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _admin_on_high_internal_service(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    bob's grant shape on a HIGH resource: the rung between bob and ines.

    Added when the sensitivity line was decided (2026-09-29): standing admin on
    HIGH is a finding, because anyone who needs admin on it should request it
    just-in-time. The decision is a label, so it lives here as ground truth
    before any rule was changed to satisfy it.
    """
    out = [
        b.identity("hugo", "Hugo Brandt", "human", "Site Reliability"),
        b.resource("internal_api_gateway", "Internal API Gateway", "server", "high"),
        b.grant(
            "g_hugo_admin",
            "hugo",
            "internal_api_gateway",
            "admin",
            lifecycle="standing",
            granted_at=b.ago(days=300),
        ),
    ]
    for day in range(0, 21):
        out.append(
            b.event(
                f"e_hugo_admin_{day}",
                "hugo",
                "internal_api_gateway",
                "assume_role",
                b.ago(days=day, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _burst_then_escalation(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Failed-auth burst followed by a successful self-grant: compromise shape."""
    out = [
        b.identity("svc_deploy", "deploy-bot", "service", "Platform Engineering"),
        b.resource("iam_control_plane", "IAM Control Plane", "cloud_account", "critical"),
        b.grant(
            "g_svc_deploy",
            "svc_deploy",
            "iam_control_plane",
            "deploy",
            lifecycle="standing",
            granted_at=b.ago(days=90),
        ),
    ]
    for i in range(12):
        out.append(
            b.event(
                f"e_svc_fail_{i}",
                "svc_deploy",
                "iam_control_plane",
                "login",
                b.ago(hours=6, minutes=40 - i * 3),
                success=False,
            )
        )
    out.append(
        b.event(
            "e_svc_login_ok",
            "svc_deploy",
            "iam_control_plane",
            "login",
            b.ago(hours=6),
            success=True,
        )
    )
    out.append(
        b.event(
            "e_svc_grant",
            "svc_deploy",
            "iam_control_plane",
            "grant_permission",
            b.ago(hours=5, minutes=50),
            success=True,
        )
    )
    return out


def _stale_connector_blind_spot(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    The failure mode a single-timestamp model cannot express.

    This identity looks quiet. It is not quiet -- the connector stopped
    delivering 14 days ago, so `observed_at` values look plausible while
    `collected_at` falls far behind. The correct output is a LOW-CONFIDENCE
    assessment, not a LOW-RISK one. An engine that conflates the two reports
    "all clear" precisely when it has gone blind.
    """
    stale_collection = b.ago(days=14)
    degraded = EvidenceQuality(
        source_reliability=0.95,
        integrity_authenticity=1.0,
        identity_mapping_confidence=1.0,
        completeness=0.4,  # we know we are missing records
    )
    return [
        b.identity("carol", "Carol Nwosu", "human", "Finance"),
        b.resource("finance_warehouse", "Finance Data Warehouse", "database", "high"),
        b.grant(
            "g_carol_write",
            "carol",
            "finance_warehouse",
            "write",
            lifecycle="standing",
            granted_at=b.ago(days=200),
            collected_at=stale_collection,
            quality=degraded,
        ),
        b.event(
            "e_carol_write",
            "carol",
            "finance_warehouse",
            "write",
            b.ago(days=15),
            collected_at=stale_collection,
            quality=degraded,
        ),
        # A second grant she has never exercised. Without this the scenario
        # proves nothing: every rule declined on carol for unrelated reasons,
        # so the negative control passed by accident and the confidence floor
        # was never exercised end to end. Now a staleness rule genuinely fires
        # and must be held back on trust grounds alone.
        b.resource("treasury_console", "Treasury Console", "api", "critical"),
        b.grant(
            "g_carol_treasury",
            "carol",
            "treasury_console",
            "admin",
            lifecycle="standing",
            granted_at=b.ago(days=180),
            collected_at=stale_collection,
            quality=degraded,
        ),
    ]


def _agent_broad_unused_access(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    An AI agent granted broad standing access "so it can do its job".

    Non-human identities acquire permissions the way scripts acquire flags -- by
    accretion, with nobody reviewing them. Wide grants plus near-zero exercise is
    the shape worth surfacing.
    """
    out = [
        b.identity("agent_triage", "triage-agent", "ai_agent", "Support Engineering"),
    ]
    resources = [
        ("ticket_store", "Ticket Store", "database", "medium"),
        ("customer_pii_db", "Customer PII Store", "database", "critical"),
        ("billing_api", "Billing API", "api", "high"),
        ("support_repo", "Support Tooling Repo", "repository", "low"),
    ]
    for res_id, name, rtype, sens in resources:
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(
                f"g_agent_{res_id}",
                "agent_triage",
                res_id,
                "write",
                lifecycle="standing",
                granted_at=b.ago(days=60),
            )
        )
    # Only ever touches the one resource it actually needs.
    for day in range(0, 14):
        out.append(
            b.event(
                f"e_agent_read_{day}",
                "agent_triage",
                "ticket_store",
                "read",
                b.ago(days=day, minutes=rng.randrange(0, 600)),
            )
        )
    return out


# --------------------------------------------------------------------------
# Corpus expansion
#
# The scenarios below exist to make detection *measurable*. Five scenarios
# cannot support a precision/recall claim -- with roughly eight labelled
# findings, a single miss moves recall by twelve points, which is noise
# masquerading as a metric.
#
# Two design rules govern everything here:
#
#   1. Negative controls are first-class. Roughly a third of these scenarios
#      assert that a factor must NOT fire. A corpus of positives only measures
#      eagerness, not accuracy: a rule returning "fire" unconditionally would
#      score perfect recall on it.
#
#   2. Several scenarios come in *discriminating pairs* -- two identities that
#      look identical in `IdentityFeatures` and differ only in something a
#      naive rule ignores. `burst_then_escalation` and
#      `failed_logins_spread_thin` both yield twelve failed logins; only one is
#      an attack. `dormant_standing_admin` and `recently_granted_not_yet_used`
#      are both unused grants; only one is stale. Pairs like these are what
#      turn a threshold from a guess into a measured choice.
# --------------------------------------------------------------------------


def _expired_grant_never_revoked(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Revocation failed silently: the TTL passed and the grant is still here."""
    return [
        b.identity("dmitri", "Dmitri Vasiliev", "human", "Platform Engineering"),
        b.resource("release_pipeline", "Release Pipeline", "cloud_account", "high"),
        b.grant(
            "g_dmitri_deploy",
            "dmitri",
            "release_pipeline",
            "deploy",
            lifecycle="time_bound",
            granted_at=b.ago(days=120),
            expires_at=b.ago(days=60),
        ),
        b.event("e_dmitri_deploy", "dmitri", "release_pipeline", "write", b.ago(days=100)),
    ]


def _jit_eligible_unused(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control, and the most important one in the corpus.

    An unused JIT-eligible grant is not a problem -- it is the *goal*. This is
    what a remediated standing grant looks like afterwards. A staleness rule
    keyed on "grant exists and was never exercised" fires here and would punish
    every successful remediation, teaching operators that fixing things makes
    their score worse.
    """
    return [
        b.identity("elena", "Elena Rossi", "human", "Site Reliability"),
        b.resource("prod_secrets", "Production Secret Store", "api", "critical"),
        b.grant(
            "g_elena_jit",
            "elena",
            "prod_secrets",
            "admin",
            lifecycle="jit_eligible",
            granted_at=b.ago(days=45),
        ),
        b.event("e_elena_read", "elena", "prod_secrets", "read", b.ago(days=2)),
    ]


def _departed_contractor_active_grants(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """No activity at all for six months, access fully intact. Offboarding missed."""
    return [
        b.identity("frank", "Frank Oyelaran", "human", "External Contractors"),
        b.resource("design_assets", "Design Asset Store", "repository", "medium"),
        b.resource("customer_records", "Customer Records DB", "database", "high"),
        b.grant(
            "g_frank_assets",
            "frank",
            "design_assets",
            "write",
            granted_at=b.ago(days=400),
        ),
        b.grant(
            "g_frank_records",
            "frank",
            "customer_records",
            "read",
            granted_at=b.ago(days=400),
        ),
        b.event("e_frank_last", "frank", "design_assets", "write", b.ago(days=190)),
    ]


def _recently_granted_not_yet_used(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: granted two days ago, not yet exercised.

    Constructed to be feature-identical to alice: one standing admin grant on a
    CRITICAL resource, zero privileged use, so `standing_permission_count`,
    `privileged_permission_count`, `standing_critical_permission_count` and
    `days_since_last_privileged_use` all match hers exactly. The only thing that
    differs is `granted_at` -- 2 days versus 420. A staleness rule that does not
    read the grant age flags every new hire in their first week, and no
    threshold on the feature vector alone can separate these two.

    EXCESSIVE_PRIVILEGE still fires here: standing admin on production is worth
    surfacing on day two. It is specifically the *staleness* claim that is wrong.
    """
    return [
        b.identity("grace", "Grace Mbeki", "human", "Platform Engineering"),
        b.resource("prod_search_cluster", "Production Search Cluster", "server", "critical"),
        b.grant(
            "g_grace_admin",
            "grace",
            "prod_search_cluster",
            "admin",
            granted_at=b.ago(days=2),
        ),
        b.event("e_grace_login", "grace", "prod_search_cluster", "login", b.ago(days=1)),
    ]


def _seasonal_quarterly_batch(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: a service account that legitimately runs once a quarter.

    Eighty-five days of silence is normal for this identity and alarming for
    most others. A fixed global staleness threshold cannot express that, which
    is the point: the corpus should punish a rule that hard-codes ninety days
    with no notion of the identity's own rhythm.
    """
    out = [
        b.identity("svc_quarterly_close", "quarterly-close-job", "service", "Finance"),
        b.resource("ledger_db", "General Ledger DB", "database", "high"),
        b.grant(
            "g_svc_ledger",
            "svc_quarterly_close",
            "ledger_db",
            "write",
            granted_at=b.ago(days=730),
        ),
    ]
    # Four clean quarterly runs. The cadence is the justification.
    for i, day in enumerate((85, 176, 267, 358)):
        out.append(
            b.event(
                f"e_svc_close_{i}",
                "svc_quarterly_close",
                "ledger_db",
                "write",
                b.ago(days=day),
            )
        )
    return out


def _admin_on_low_sensitivity_sandbox(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: standing admin, deliberately, on a throwaway sandbox.

    Catches a rule that keys on the action alone. `admin` is only alarming in
    proportion to what it is admin *over*; firing here trains operators to
    ignore the finding everywhere.
    """
    out = [
        b.identity("henry", "Henry Takahashi", "human", "Developer Experience"),
        b.resource("dev_sandbox", "Developer Sandbox", "server", "low"),
        b.grant(
            "g_henry_sandbox",
            "henry",
            "dev_sandbox",
            "admin",
            granted_at=b.ago(days=150),
        ),
    ]
    for day in range(0, 12, 2):
        out.append(
            b.event(
                f"e_henry_sandbox_{day}",
                "henry",
                "dev_sandbox",
                "assume_role",
                b.ago(days=day, hours=rng.randrange(0, 9)),
            )
        )
    return out


def _read_only_analyst_wide_access(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control for blast radius: six resources, but read-only and low value.

    Breadth alone is not blast radius. A rule counting grants without weighting
    action and sensitivity flags the entire analytics organisation.
    """
    out = [b.identity("iris", "Iris Kowalski", "human", "Business Intelligence")]
    catalog = (
        ("sales_marts", "Sales Data Marts", "database", "low"),
        ("marketing_events", "Marketing Event Stream", "api", "low"),
        ("product_metrics", "Product Metrics DB", "database", "medium"),
        ("support_metrics", "Support Metrics DB", "database", "low"),
        ("web_analytics", "Web Analytics API", "api", "low"),
        ("bi_dashboards", "BI Dashboard Repo", "repository", "low"),
    )
    for idx, (res_id, name, rtype, sens) in enumerate(catalog):
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(
                f"g_iris_{res_id}",
                "iris",
                res_id,
                "read",
                granted_at=b.ago(days=220),
            )
        )
        out.append(
            b.event(
                f"e_iris_{res_id}",
                "iris",
                res_id,
                "read",
                b.ago(days=idx, hours=rng.randrange(0, 10)),
            )
        )
    return out


def _delete_on_critical_never_used(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Standing delete on a crown jewel, never once exercised. Pure downside."""
    return [
        b.identity("julia", "Julia Ferreira", "human", "Data Platform"),
        b.resource("event_archive", "Event Archive", "database", "critical"),
        b.grant(
            "g_julia_delete",
            "julia",
            "event_archive",
            "delete",
            granted_at=b.ago(days=310),
        ),
        b.event("e_julia_read", "julia", "event_archive", "read", b.ago(days=4)),
    ]


def _service_account_sprawl(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A CI account that accreted admin across the estate, one "just this once" at a time.

    Service identities are where blast radius grows fastest: nobody is offboarded,
    nobody reviews them, and every incident adds one more grant.
    """
    out = [b.identity("svc_ci_runner", "ci-runner", "service", "Platform Engineering")]
    catalog = (
        ("build_farm", "Build Farm", "server", "medium"),
        ("artifact_registry", "Artifact Registry", "repository", "high"),
        ("prod_k8s", "Production Kubernetes", "cloud_account", "critical"),
        ("payments_gateway", "Payments Gateway", "api", "critical"),
        ("infra_state", "Terraform State Bucket", "cloud_account", "high"),
        ("monitoring_stack", "Monitoring Stack", "server", "medium"),
    )
    for idx, (res_id, name, rtype, sens) in enumerate(catalog):
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(
                f"g_ci_{res_id}",
                "svc_ci_runner",
                res_id,
                "admin",
                granted_at=b.ago(days=365 - idx * 55),
            )
        )
    # It only ever actually builds things.
    for day in range(0, 10):
        out.append(
            b.event(
                f"e_ci_build_{day}",
                "svc_ci_runner",
                "build_farm",
                "write",
                b.ago(days=day, hours=rng.randrange(0, 12)),
            )
        )
    return out


def _agent_scope_accretion(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    An AI agent whose scope grew monthly, each grant individually reasonable.

    The grant timestamps are the signal: five grants added on a steady cadence
    is a process with no brake on it, which is a different finding from a single
    over-broad grant issued once.
    """
    out = [b.identity("agent_ops", "ops-copilot", "ai_agent", "Platform Engineering")]
    catalog = (
        ("runbook_repo", "Runbook Repository", "repository", "low", 150),
        ("alert_api", "Alerting API", "api", "medium", 120),
        ("log_store", "Central Log Store", "database", "high", 90),
        ("config_service", "Config Service", "api", "high", 60),
        ("prod_db_replica", "Production DB Replica", "database", "critical", 30),
    )
    for res_id, name, rtype, sens, granted_days in catalog:
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(
                f"g_agent_ops_{res_id}",
                "agent_ops",
                res_id,
                "write",
                granted_at=b.ago(days=granted_days),
            )
        )
    for day in range(0, 8):
        out.append(
            b.event(
                f"e_agent_ops_{day}",
                "agent_ops",
                "alert_api",
                "read",
                b.ago(days=day, minutes=rng.randrange(0, 900)),
            )
        )
    return out


def _revoke_then_regrant(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Revoke immediately followed by re-grant: the shape of covering tracks.

    Either permission alone is unremarkable. The ordering and the four-minute
    gap are the finding, which a rule counting admin events cannot see.
    """
    return [
        b.identity("svc_automation", "automation-bot", "service", "Corporate IT"),
        b.resource("directory_service", "Corporate Directory", "api", "critical"),
        b.grant(
            "g_svc_directory",
            "svc_automation",
            "directory_service",
            "admin",
            granted_at=b.ago(days=200),
        ),
        b.event(
            "e_auto_revoke",
            "svc_automation",
            "directory_service",
            "revoke_permission",
            b.ago(days=3, minutes=12),
        ),
        b.event(
            "e_auto_regrant",
            "svc_automation",
            "directory_service",
            "grant_permission",
            b.ago(days=3, minutes=8),
        ),
    ]


def _assume_role_chain(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Four assume_role hops in nine minutes, ending at the crown jewel.

    Each hop is authorised. The chain is the attack, and only the sequence
    reveals it -- another case where per-event evaluation is blind.
    """
    out = [
        b.identity("kwame", "Kwame Asante", "human", "Data Engineering"),
        b.resource("jump_host", "Jump Host", "server", "medium"),
        b.resource("data_platform", "Data Platform Account", "cloud_account", "high"),
        b.resource("prod_account", "Production Account", "cloud_account", "critical"),
        b.resource("hsm_vault", "HSM Key Vault", "api", "critical"),
        # Impersonation, not admin. Under the old vocabulary this had to be
        # flattened to "admin" because there was no member for "may assume
        # other roles" -- the capability his whole scenario is about.
        b.grant(
            "g_kwame_jump", "kwame", "jump_host", "impersonate", granted_at=b.ago(days=180)
        ),
    ]
    hops = (
        ("jump_host", 9),
        ("data_platform", 6),
        ("prod_account", 3),
        ("hsm_vault", 1),
    )
    for idx, (res_id, minutes) in enumerate(hops):
        out.append(
            b.event(
                f"e_kwame_hop_{idx}",
                "kwame",
                res_id,
                "assume_role",
                b.ago(days=2, minutes=minutes),
            )
        )
    return out


def _legitimate_onboarding_grants(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: an IT admin issuing six grants in an afternoon.

    This is onboarding, and it looks exactly like a privilege-escalation burst
    to any rule that counts `grant_permission` events. What separates them is
    who the grants were *for* -- which this engine cannot yet see, so the honest
    outcome today is a low-confidence finding rather than a confident one.
    """
    out = [
        b.identity("laura", "Laura Nkemdirim", "human", "Corporate IT"),
        b.resource("iam_console", "IAM Console", "api", "high"),
        b.grant(
            "g_laura_iam",
            "laura",
            "iam_console",
            "manage_permission",
            granted_at=b.ago(days=800),
        ),
    ]
    for i in range(6):
        out.append(
            b.event(
                f"e_laura_grant_{i}",
                "laura",
                "iam_console",
                "grant_permission",
                b.ago(days=5, hours=-9, minutes=i * 11),
            )
        )
    # Two years of steady, boring administration is the exonerating context.
    for week in range(1, 20):
        out.append(
            b.event(
                f"e_laura_routine_{week}",
                "laura",
                "iam_console",
                "grant_permission",
                b.ago(days=week * 7, hours=-10),
            )
        )
    return out


def _credential_stuffing_no_success(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Thirty failed logins, none successful.

    Pairs with `burst_then_escalation`: the burst is real and must fire, but
    nothing was compromised, so escalation must NOT. A rule that treats a failed
    burst as evidence of takeover manufactures an incident out of a blocked one.
    """
    out = [
        b.identity("svc_legacy_sync", "legacy-sync", "service", "Corporate IT"),
        b.resource("legacy_erp", "Legacy ERP", "server", "high"),
        b.grant(
            "g_svc_erp",
            "svc_legacy_sync",
            "legacy_erp",
            "read",
            granted_at=b.ago(days=1000),
        ),
    ]
    for i in range(30):
        out.append(
            b.event(
                f"e_stuff_{i}",
                "svc_legacy_sync",
                "legacy_erp",
                "login",
                b.ago(hours=9, minutes=55 - i),
                success=False,
            )
        )
    return out


def _failed_logins_spread_thin(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: twelve failed logins spread across thirty days.

    The sharpest pair in the corpus. `burst_then_escalation` also produces
    twelve failed logins, so `failed_authentication_count` is identical for both
    identities -- twelve. One is a credential attack compressed into forty
    minutes; this one is a human mistyping a password twice a week. Any rule
    keyed on the count rather than the rate scores both the same and is wrong
    exactly half the time.
    """
    out = [
        b.identity("marcus", "Marcus Bergstrom", "human", "Sales"),
        b.resource("crm_platform", "CRM Platform", "api", "medium"),
        b.grant(
            "g_marcus_crm",
            "marcus",
            "crm_platform",
            "write",
            granted_at=b.ago(days=500),
        ),
    ]
    for i in range(12):
        day = i * 2 + rng.randrange(0, 2)
        out.append(
            b.event(
                f"e_marcus_fail_{i}",
                "marcus",
                "crm_platform",
                "login",
                b.ago(days=day, hours=-8),
                success=False,
            )
        )
        out.append(
            b.event(
                f"e_marcus_ok_{i}",
                "marcus",
                "crm_platform",
                "login",
                b.ago(days=day, hours=-8, minutes=-2),
            )
        )
    return out


def _mass_delete_burst(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Forty deletes on a critical archive inside two hours. Destruction or exfil cleanup."""
    out = [
        b.identity("svc_retention", "retention-worker", "service", "Data Platform"),
        b.resource("audit_archive", "Audit Log Archive", "database", "critical"),
        b.grant(
            "g_svc_retention",
            "svc_retention",
            "audit_archive",
            "delete",
            granted_at=b.ago(days=150),
        ),
    ]
    for i in range(40):
        out.append(
            b.event(
                f"e_retention_del_{i}",
                "svc_retention",
                "audit_archive",
                "delete",
                b.ago(hours=4, minutes=110 - i * 3),
            )
        )
    return out


def _dormant_then_sudden_activity(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Silent for four months, then thirty actions today. Classic account takeover.

    Neither half is suspicious alone: dormancy is common and a busy day is
    normal. The transition is the signal, and it needs a baseline rather than a
    threshold.
    """
    out = [
        b.identity("nadia", "Nadia Haddad", "human", "Legal"),
        b.resource("contract_vault", "Contract Vault", "database", "high"),
        b.grant(
            "g_nadia_contracts",
            "nadia",
            "contract_vault",
            "write",
            granted_at=b.ago(days=600),
        ),
    ]
    for i in range(4):
        out.append(
            b.event(
                f"e_nadia_old_{i}",
                "nadia",
                "contract_vault",
                "read",
                b.ago(days=120 + i * 8),
            )
        )
    for i in range(30):
        out.append(
            b.event(
                f"e_nadia_burst_{i}",
                "nadia",
                "contract_vault",
                "read",
                b.ago(hours=3, minutes=170 - i * 5),
            )
        )
    return out


def _department_context_mismatch(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A Marketing employee holding standing admin on the payments database.

    No individual fact here is anomalous -- the grant is real, the department is
    real. Only the combination is absurd, which is what makes this a context
    finding rather than a privilege one.

    The four Finance co-holders are the peer group that makes "absurd"
    measurable (added 2026-09-29 with `peer_access_outlier`). They hold read,
    use it, and are unlabelled: they exist to be the baseline, not to be
    judged. Without them the rule would have no one to compare oscar to.
    """
    out = [
        b.identity("oscar", "Oscar Lindqvist", "human", "Marketing"),
        b.resource("payments_ledger", "Payments Ledger", "database", "critical"),
        b.grant(
            "g_oscar_payments",
            "oscar",
            "payments_ledger",
            "admin",
            granted_at=b.ago(days=95),
        ),
        b.event("e_oscar_read", "oscar", "payments_ledger", "read", b.ago(days=6)),
    ]
    out += _ledger_peers(b, rng, "payments_ops", "payments_ledger")
    return out


def _ledger_peers(
    b: EvidenceBuilder, rng: random.Random, prefix: str, resource_id: str
) -> list[Evidence]:
    """Four Finance analysts with standing read on a ledger, used every few days."""
    out: list[Evidence] = []
    for i in range(4):
        who = f"{prefix}_{i}"
        out.append(b.identity(who, f"Finance Analyst {prefix} {i}", "human", "Finance"))
        out.append(
            b.grant(f"g_{who}", who, resource_id, "read", granted_at=b.ago(days=300))
        )
        for day in range(0, 21, 3):
            out.append(
                b.event(
                    f"e_{who}_{day}",
                    who,
                    resource_id,
                    "read",
                    b.ago(days=day, hours=rng.randrange(0, 8)),
                )
            )
    return out


def _service_account_interactive_login(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A service identity performing interactive logins.

    Service accounts authenticate with keys, not sessions. Successful `login`
    events on one usually mean a human is wearing it -- which destroys
    attribution and is why shared service credentials are worth surfacing.
    """
    out = [
        b.identity("svc_reporting", "reporting-svc", "service", "Finance"),
        b.resource("finance_bi", "Finance BI Warehouse", "database", "high"),
        b.grant(
            "g_svc_reporting",
            "svc_reporting",
            "finance_bi",
            "read",
            granted_at=b.ago(days=420),
        ),
    ]
    for i in range(9):
        out.append(
            b.event(
                f"e_svc_interactive_{i}",
                "svc_reporting",
                "finance_bi",
                "login",
                b.ago(days=i * 2, hours=-14),
            )
        )
    return out


def _incomplete_but_fresh_collection(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    The second blind spot, and deliberately not the same as the first.

    `stale_connector_blind_spot` is a connector that stopped: fresh-looking
    facts, stale `collected_at`. This one is a connector that is running
    perfectly but only sees part of the estate -- current `collected_at`,
    `completeness=0.5`. Both must suppress confidence, and an engine keyed on
    collection lag alone catches only the first.
    """
    partial = EvidenceQuality(
        source_reliability=0.9,
        integrity_authenticity=1.0,
        identity_mapping_confidence=0.6,  # we are not sure this is the same person
        completeness=0.5,
    )
    return [
        b.identity("priya", "Priya Raghunathan", "human", "Engineering"),
        b.resource("source_monorepo", "Source Monorepo", "repository", "high"),
        b.grant(
            "g_priya_repo",
            "priya",
            "source_monorepo",
            "write",
            granted_at=b.ago(days=260),
            quality=partial,
        ),
        b.event(
            "e_priya_push",
            "priya",
            "source_monorepo",
            "write",
            b.ago(days=40),
            quality=partial,
        ),
        # As with carol: a grant that genuinely trips a rule, so the control
        # tests suppression rather than coincidence.
        b.resource("release_signing", "Release Signing Service", "api", "critical"),
        b.grant(
            "g_priya_signing",
            "priya",
            "release_signing",
            "admin",
            granted_at=b.ago(days=150),
            quality=partial,
        ),
    ]


def _public_bucket_standing_write(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Standing write on an internet-facing bucket holding customer exports.

    The toxic combination: privileged, standing, critical *and* reachable from
    outside. Any one of those alone is routine. Together they are the shape of
    every "misconfigured bucket" breach writeup ever published.
    """
    out = [
        b.identity("quentin", "Quentin Adeyemi", "human", "Data Platform"),
        b.resource(
            "export_bucket",
            "Customer Export Bucket",
            "cloud_account",
            "critical",
            exposure="public",
        ),
        b.grant(
            "g_quentin_exports",
            "quentin",
            "export_bucket",
            "admin",
            granted_at=b.ago(days=210),
        ),
    ]
    for day in range(0, 6):
        out.append(
            b.event(
                f"e_quentin_write_{day}",
                "quentin",
                "export_bucket",
                "write",
                b.ago(days=day, hours=rng.randrange(0, 11)),
            )
        )
    return out


def _public_by_design_marketing_site(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: a resource that is public because it is supposed to be.

    The essential counterweight to `public_bucket_standing_write`. Exposure is
    not a defect -- a marketing site nobody can reach is a broken marketing
    site. A rule that fires on `exposure == PUBLIC` alone flags every CDN,
    status page and docs site in the estate, which is how an exposure feature
    becomes an ignored one. What matters is exposure *joined to* sensitivity
    and privilege, and here both of those are floor-level.
    """
    out = [
        b.identity("rosa", "Rosa Delgado", "human", "Marketing"),
        b.resource(
            "public_website",
            "Public Marketing Site",
            "api",
            "low",
            exposure="public",
        ),
        b.resource(
            "status_page",
            "Public Status Page",
            "api",
            "low",
            exposure="public",
        ),
    ]
    for res_id in ("public_website", "status_page"):
        out.append(
            b.grant(
                f"g_rosa_{res_id}",
                "rosa",
                res_id,
                "write",
                granted_at=b.ago(days=300),
            )
        )
    for day in range(0, 10, 2):
        out.append(
            b.event(
                f"e_rosa_publish_{day}",
                "rosa",
                "public_website",
                "write",
                b.ago(days=day, hours=rng.randrange(0, 9)),
            )
        )
    return out


def _external_partner_critical_access(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    The identity side of exposure: a third-party principal, not a third-party resource.

    The resource here is strictly internal, so every resource-side exposure
    check reads clean. The reachability comes from *who holds the grant* -- a
    partner tenant outside our identity provider, whose own compromise becomes
    ours. Supply-chain access looks exactly like this in an IAM dump, which is
    why exposure has to be modelled on both sides.
    """
    return [
        b.identity(
            "partner_integrator",
            "NorthBridge Integrations",
            "service",
            "External Partners",
            is_external=True,
        ),
        b.resource("claims_db", "Insurance Claims DB", "database", "critical"),
        b.grant(
            "g_partner_claims",
            "partner_integrator",
            "claims_db",
            "write",
            granted_at=b.ago(days=180),
        ),
        b.event(
            "e_partner_write", "partner_integrator", "claims_db", "write", b.ago(days=9)
        ),
    ]


def _finance_admin_on_finance_db(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control for context: the access fits the person exactly.

    Pairs with `department_context_mismatch`. oscar and sonia both hold standing
    admin on a CRITICAL finance database and both use it. The only difference is
    the department attribute -- Marketing versus Finance. A context rule must
    read that attribute; a privilege rule must ignore it and fire on both.
    """
    out = [
        b.identity("sonia", "Sonia Varga", "human", "Finance"),
        b.resource("finance_ledger", "Finance Ledger", "database", "critical"),
        b.grant(
            "g_sonia_ledger",
            "sonia",
            "finance_ledger",
            "admin",
            granted_at=b.ago(days=240),
        ),
    ]
    for day in range(0, 14, 2):
        out.append(
            b.event(
                f"e_sonia_ledger_{day}",
                "sonia",
                "finance_ledger",
                "write",
                b.ago(days=day, hours=rng.randrange(0, 9)),
            )
        )
    # sonia's peers, so the context control is *evaluated* and declines,
    # rather than passing because no peer group existed (lesson 8.4).
    out += _ledger_peers(b, rng, "finance_ops", "finance_ledger")
    return out


def _dormant_permission_manager(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Standing permission-management rights over the IAM control plane, unused.

    The scenario the old vocabulary could not express. Under `PermissionAction`
    this identity's grant had to be flattened to `admin` or `write`, and the
    single most dangerous capability in an estate -- the one that can grant
    every other capability -- was indistinguishable from ordinary access until
    it was exercised.
    """
    return [
        b.identity("viktor", "Viktor Novak", "human", "Corporate IT"),
        b.resource("iam_control_plane_eu", "EU IAM Control Plane", "cloud_account", "critical"),
        b.grant(
            "g_viktor_iam",
            "viktor",
            "iam_control_plane_eu",
            "manage_permission",
            lifecycle="standing",
            granted_at=b.ago(days=280),
        ),
        b.event("e_viktor_read", "viktor", "iam_control_plane_eu", "read", b.ago(days=5)),
    ]


def _jit_permission_manager(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: the same dangerous capability, held the right way.

    Pairs with `dormant_permission_manager`. Identical capability on an equally
    critical resource -- only `GrantLifecycle` differs. This is what the
    remediation of viktor looks like, and an engine that fires on the
    capability alone would report no improvement after the fix, which is the
    fastest way to stop anyone doing the fix.
    """
    out = [
        b.identity("wendy", "Wendy Achterberg", "human", "Corporate IT"),
        b.resource("iam_control_plane_us", "US IAM Control Plane", "cloud_account", "critical"),
        b.grant(
            "g_wendy_iam",
            "wendy",
            "iam_control_plane_us",
            "manage_permission",
            lifecycle="jit_eligible",
            granted_at=b.ago(days=120),
        ),
    ]
    for day in range(0, 9, 3):
        out.append(
            b.event(
                f"e_wendy_grant_{day}",
                "wendy",
                "iam_control_plane_us",
                "grant_permission",
                b.ago(days=day, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _entitlements_admin(
    b: EvidenceBuilder,
    identity_id: str,
    name: str,
    tool: tuple[str, str],
    governed: tuple[tuple[str, str, str], ...],
) -> list[Evidence]:
    """
    Standing permission management on a MEDIUM internal tool, used every few
    days. What the tool *governs* is the only thing the pair varies.
    """
    tool_id, tool_name = tool
    out = [
        b.identity(identity_id, name, "human", "Business Systems"),
        b.resource(tool_id, tool_name, "api", "medium",
                   governs=tuple(res_id for res_id, _, _ in governed)),
        b.grant(f"g_{identity_id}_tool", identity_id, tool_id, "manage_permission",
                granted_at=b.ago(days=400)),
    ]
    out += [b.resource(res_id, res_name, "database", sens) for res_id, res_name, sens in governed]
    for i, day in enumerate(range(1, 60, 4)):
        out.append(b.event(f"e_{identity_id}_grant_{i}", identity_id, tool_id,
                           "grant_permission", b.ago(days=day, hours=3)))
    return out


def _governed_crown_jewel(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Permission management on a mid-tier tool that controls a CRITICAL ledger.

    Every grant-level check reads clean: the grant sits on a MEDIUM resource,
    so `standing_permission_management.v1` -- which judged the resource the
    grant is *on* -- stayed quiet. But whoever manages the tool's permission
    table decides who holds the treasury ledger, including themselves. The
    finding lives one `governs` hop away from the grant; v2 reads it through
    effective reach.
    """
    return _entitlements_admin(
        b, "gustav", "Gustav Lindqvist",
        ("treasury_entitlements", "Treasury Entitlements Tool"),
        (("treasury_payments_ledger", "Treasury Payments Ledger", "critical"),),
    )


def _governed_low_value_only(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: the same grant on the same kind of tool, governing only
    LOW resources. Pairs with `governed_crown_jewel`; feature-identical, and
    only the governed sensitivity differs. A rule that fires on "manages a
    control plane" rather than on what the plane controls fires here.
    """
    return _entitlements_admin(
        b, "hanna", "Hanna Okafor",
        ("wiki_entitlements", "Wiki Entitlements Tool"),
        (
            ("handbook_wiki", "Employee Handbook Wiki", "low"),
            ("lunch_rota", "Office Lunch Rota", "low"),
        ),
    )


def _unmapped_capability_grants(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A source whose action vocabulary this taxonomy does not understand.

    The failure mode the capability model must survive. Three of four grants
    carry provider-specific action strings with no mapping, so they normalize
    to `Capability.UNKNOWN`.

    Two things must hold, and they pull in opposite directions:

      * The grants are **retained**. Dropping them -- which is what the old
        `_parse_enum` did, turning each into a NormalizationIssue -- understates
        access, the one direction this engine must never err in.
      * Nothing is reported **confidently**. We do not know what this identity
        can do, and a clean report would be a lie told with a straight face.

    Retention plus suppressed confidence is how both hold at once.
    """
    out = [
        b.identity("yusuf", "Yusuf Demirci", "human", "Data Platform"),
        b.resource("vendor_platform", "Vendor Analytics Platform", "api", "critical"),
        b.grant(
            "g_yusuf_known",
            "yusuf",
            "vendor_platform",
            "read",
            granted_at=b.ago(days=200),
        ),
    ]
    # Vocabulary from a system nobody has written a mapping table for yet.
    for idx, action in enumerate(
        ("vendorx.superuser", "vendorx.pipeline.orchestrate", "vendorx.tenant.rebind")
    ):
        out.append(
            b.grant(
                f"g_yusuf_opaque_{idx}",
                "yusuf",
                "vendor_platform",
                action,
                granted_at=b.ago(days=200 - idx * 20),
            )
        )
    out.append(
        b.event("e_yusuf_read", "yusuf", "vendor_platform", "read", b.ago(days=3))
    )
    return out


def _standing_identity_manager(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A helpdesk automation account that can mint credentials for anyone, forever.

    `MANAGE_IDENTITY` is the quieter sibling of `MANAGE_PERMISSION` and in some
    ways the worse one: rather than granting itself rights under its own name,
    this identity can create a principal, hand it any entitlement, and act as
    somebody else entirely. The audit trail then points at a user who never
    touched a keyboard.

    Never exercised in the window, which is the usual state of these grants --
    issued during an integration project, wired into nothing, never revoked.
    """
    return [
        b.identity("svc_helpdesk", "helpdesk-automation", "service", "Corporate IT"),
        b.resource("employee_directory", "Employee Directory", "api", "critical"),
        b.grant(
            "g_helpdesk_identity",
            "svc_helpdesk",
            "employee_directory",
            "manage_identity",
            lifecycle="standing",
            granted_at=b.ago(days=340),
        ),
        b.event(
            "e_helpdesk_read", "svc_helpdesk", "employee_directory", "read", b.ago(days=2)
        ),
    ]


def _scoped_identity_manager(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: the same capability, time-boxed and actively used.

    Pairs with `standing_identity_manager`. Identical capability on an equally
    critical directory; the grant expires in nine days and is exercised weekly.
    This is what a scoped, reviewed entitlement looks like, and firing on the
    capability alone would make "we time-boxed it" indistinguishable from "we
    left it standing" -- which removes any reason to do the former.
    """
    out = [
        b.identity("zainab", "Zainab Farooqi", "human", "People Operations"),
        b.resource("hr_directory", "HR Directory", "api", "critical"),
        b.grant(
            "g_zainab_identity",
            "zainab",
            "hr_directory",
            "manage_identity",
            lifecycle="time_bound",
            granted_at=b.ago(days=21),
            expires_at=b.ago(days=-9),  # nine days in the future
        ),
    ]
    for day in (2, 9, 16):
        out.append(
            b.event(
                f"e_zainab_grant_{day}",
                "zainab",
                "hr_directory",
                "grant_permission",
                b.ago(days=day, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _security_control_tamper_rights(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Standing rights over the audit pipeline itself.

    The uniquely bad capability: this identity can stop the logging that would
    record what it did next, which means every other detection in this engine
    -- including the ones watching this identity -- can be switched off from
    the inside.

    Actively used, deliberately. Staleness must not fire here, so the finding
    has to rest on what the grant *confers* rather than on disuse: an engine
    that only reports unused grants would never surface the most dangerous
    permission in the estate as long as somebody keeps touching it.
    """
    out = [
        b.identity("svc_observability", "observability-operator", "service", "Site Reliability"),
        b.resource("audit_pipeline", "Audit Log Pipeline", "cloud_account", "critical"),
        b.grant(
            "g_obs_controls",
            "svc_observability",
            "audit_pipeline",
            "manage_security_control",
            lifecycle="standing",
            granted_at=b.ago(days=190),
        ),
    ]
    for day in range(0, 12, 3):
        out.append(
            b.event(
                f"e_obs_tune_{day}",
                "svc_observability",
                "audit_pipeline",
                "write",
                b.ago(days=day, hours=rng.randrange(0, 10)),
            )
        )
    return out


def _security_control_read_only(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: can watch the monitoring, cannot switch it off.

    Pairs with `security_control_tamper_rights` on the same class of resource.
    Reading dashboards is what an on-call engineer does all day; a rule keyed
    on the resource being a security control, rather than on the capability
    held over it, would page somebody about every SRE on the roster.
    """
    out = [
        b.identity("tomas", "Tomas Sandberg", "human", "Site Reliability"),
        b.resource("siem_platform", "SIEM Platform", "server", "critical"),
        b.grant(
            "g_tomas_siem",
            "tomas",
            "siem_platform",
            "read",
            lifecycle="standing",
            granted_at=b.ago(days=260),
        ),
    ]
    for day in range(0, 10, 2):
        out.append(
            b.event(
                f"e_tomas_read_{day}",
                "tomas",
                "siem_platform",
                "read",
                b.ago(days=day, hours=rng.randrange(0, 11)),
            )
        )
    return out


def _dormant_cross_account_role(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Standing rights to assume a role into the production account, never used.

    Impersonation is the capability that makes access paths traversable: it
    does not grant anything directly, it grants the ability to *become* someone
    who has it. That indirection is why it reads as harmless in a permissions
    dump and why `assume_role_chain` is possible at all -- and, like every
    capability here, holding it is the finding rather than exercising it.
    """
    return [
        b.identity("rahul", "Rahul Menon", "human", "Data Engineering"),
        b.resource("prod_trading_account", "Production Trading Account", "cloud_account", "critical"),
        b.grant(
            "g_rahul_assume",
            "rahul",
            "prod_trading_account",
            "impersonate",
            lifecycle="standing",
            granted_at=b.ago(days=395),
        ),
        b.event(
            "e_rahul_read", "rahul", "prod_trading_account", "read", b.ago(days=7)
        ),
    ]


# --------------------------------------------------------------------------
# Tier 2 training pairs (2026-09-29)
#
# One positive and one trap per new detection, all in TRAIN, written before
# the rules they constrain. A rule written against a positive alone learns
# "fire on this identity"; the trap is what makes it learn the reason.
# --------------------------------------------------------------------------


def _scheduled_job(
    b: EvidenceBuilder,
    identity_id: str,
    name: str,
    department: str,
    resource: tuple[str, str],
    run_days_ago: tuple[int, ...],
) -> list[Evidence]:
    """A service identity that writes to one HIGH resource on a schedule."""
    res_id, res_name = resource
    out = [
        b.identity(identity_id, name, "service", department),
        b.resource(res_id, res_name, "database", "high"),
        b.grant(f"g_{identity_id}", identity_id, res_id, "write", granted_at=b.ago(days=900)),
    ]
    for i, day in enumerate(run_days_ago):
        out.append(b.event(f"e_{identity_id}_{i}", identity_id, res_id, "write", b.ago(days=day)))
    return out


def _semiannual_job_on_cadence(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control: a half-yearly audit export, 120 days into its cycle.

    Four runs 182 days apart establish the rhythm. 120 days of silence is past
    the 90-day global floor -- dormancy v1 fired here -- and well inside this
    identity's own cycle. The TRAIN-side twin of the holdout's
    `seasonal_quarterly_batch`.
    """
    return _scheduled_job(
        b,
        "svc_semiannual_audit",
        "semiannual-audit-export",
        "Internal Audit",
        ("audit_evidence_store", "Audit Evidence Store"),
        (120, 302, 484, 666),
    )


def _quarterly_job_missed_runs(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A quarterly reconciliation job that silently stopped: last run 160 days ago.

    Five runs 91 days apart, then nothing through the next scheduled run. The
    positive that keeps the cadence baseline honest: a rhythm-aware rule that
    tolerated any silence shorter than two cycles would miss exactly this.
    """
    return _scheduled_job(
        b,
        "svc_quarterly_recon",
        "quarterly-recon-job",
        "Treasury Operations",
        ("recon_db", "Reconciliation DB"),
        (160, 251, 342, 433, 524),
    )


def _onboarding_batch_grants(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control for creep: agent_ops's five grants, issued in one afternoon.

    Same sensitivities, same capability, same usage (it only reads its queue).
    The only difference is the grant dates: one provisioning event 150 days
    ago rather than one grant a month. Over-provisioned and stale, yes -- both
    labelled -- but not creep.
    """
    out = [b.identity("agent_intake", "intake-copilot", "ai_agent", "Platform Engineering")]
    catalog = (
        ("intake_runbooks", "Intake Runbooks", "repository", "low"),
        ("intake_queue", "Intake Queue API", "api", "medium"),
        ("intake_logs", "Intake Log Store", "database", "high"),
        ("intake_config", "Intake Config Service", "api", "high"),
        ("intake_db_replica", "Intake DB Replica", "database", "critical"),
    )
    for res_id, name, rtype, sens in catalog:
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(
                f"g_agent_intake_{res_id}",
                "agent_intake",
                res_id,
                "write",
                granted_at=b.ago(days=150),
            )
        )
    for day in range(0, 8):
        out.append(
            b.event(
                f"e_agent_intake_{day}",
                "agent_intake",
                "intake_queue",
                "read",
                b.ago(days=day, minutes=rng.randrange(0, 900)),
            )
        )
    return out


def _weekly_reader(
    b: EvidenceBuilder,
    rng: random.Random,
    identity_id: str,
    name: str,
    resource: tuple[str, str, str],
) -> list[Evidence]:
    """A human with standing read on one CRITICAL resource, used weekly."""
    res_id, res_name, rtype = resource
    out = [
        b.identity(identity_id, name, "human", "Application Engineering"),
        b.resource(res_id, res_name, rtype, "critical"),
        b.grant(f"g_{identity_id}", identity_id, res_id, "read", granted_at=b.ago(days=250)),
    ]
    for week in range(0, 9):
        out.append(
            b.event(
                f"e_{identity_id}_{week}",
                identity_id,
                res_id,
                "read",
                b.ago(days=week * 7, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _standing_read_on_secret_store(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Standing read on the production vault. "Read-only" is the wrong word for it.

    Pairs with `standing_read_on_critical_db`: identical but for the resource
    type. Read on a database is read; read on a vault is every credential in it.
    """
    return _weekly_reader(
        b, rng, "otto", "Otto Lindahl", ("prod_vault", "Production Vault", "secret_store")
    )


def _standing_read_on_critical_db(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Negative control: otto's grant shape on an ordinary CRITICAL database."""
    return _weekly_reader(
        b, rng, "pablo", "Pablo Ferreira", ("orders_db", "Orders Database", "database")
    )


def _read_burst(
    b: EvidenceBuilder,
    identity_id: str,
    res_id: str,
    tag: str,
    count: int,
    when: datetime,
    span_min: int,
) -> list[Evidence]:
    """
    `count` reads spread evenly over `span_min` minutes starting at `when`.

    Ids come from `tag`, never from the timestamp: a timestamp-derived id makes
    night n under one anchor byte-identical to night n-1 under the next, which
    is a real collision `test_no_wall_clock_dependency` exists to catch.
    """
    return [
        b.event(
            f"e_{identity_id}_{tag}_{i}",
            identity_id,
            res_id,
            "read",
            when + timedelta(minutes=span_min * i / count),
        )
        for i in range(count)
    ]


def _bulk_export_after_quiet_history(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Two months of a couple of reads a day, then 80 reads in 40 minutes.

    The exfiltration shape. Nothing is unauthorised -- he holds read on the
    export DB and has used it for months. The finding is the volume relative
    to his own history.
    """
    out = [
        b.identity("ravi", "Ravi Menon", "human", "Customer Success"),
        b.resource("customer_export_db", "Customer Export DB", "database", "critical"),
        b.grant("g_ravi_export", "ravi", "customer_export_db", "read", granted_at=b.ago(days=400)),
    ]
    for day in range(3, 64):
        for k in range(2):
            out.append(
                b.event(
                    f"e_ravi_daily_{day}_{k}",
                    "ravi",
                    "customer_export_db",
                    "read",
                    b.ago(days=day, hours=9 - 4 * k, minutes=rng.randrange(0, 50)),
                )
            )
    out += _read_burst(
        b, "ravi", "customer_export_db", "burst", 80, b.ago(days=2, hours=-14), 40
    )
    return out


def _nightly_etl_on_schedule(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Negative control for bulk reads: 80 reads in 40 minutes, every night.

    ravi's burst volume, as a routine. Any global volume threshold low enough
    to catch ravi flags this job every night; only a baseline tells them apart.
    """
    out = [
        b.identity("svc_nightly_etl", "nightly-etl", "service", "Data Engineering"),
        b.resource("sales_warehouse", "Sales Warehouse", "database", "high"),
        b.grant(
            "g_svc_nightly_etl", "svc_nightly_etl", "sales_warehouse", "read",
            granted_at=b.ago(days=500),
        ),
    ]
    for night in range(0, 20):
        out += _read_burst(
            b, "svc_nightly_etl", "sales_warehouse", f"night{night}", 80,
            b.ago(days=night, hours=22), 40,
        )
    return out


# --------------------------------------------------------------------------
# Calibration cycle 2 training cases (2026-09-29)
#
# The first FRESH reading failed on three *shapes*: an emergency account, a
# long-cycle job with little history, and a department that is a minority but
# not absent among a resource's holders. These are new TRAIN cases of the same
# shapes -- deliberately not copies of the FRESH scenarios, which are spent --
# plus positives that pin each loosened threshold from the other side, and
# middle cases for the two thresholds TRAIN left almost unconstrained.
# --------------------------------------------------------------------------


def _emergency_db_break_glass(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A tagged break-glass account: standing admin on the payments core, never used."""
    return [
        b.identity(
            "breakglass_payments", "break-glass-payments", "human", "Security Operations",
            is_break_glass=True,
        ),
        b.resource("payments_core_db", "Payments Core DB", "database", "critical"),
        b.grant(
            "g_breakglass_payments", "breakglass_payments", "payments_core_db", "admin",
            granted_at=b.ago(days=500),
        ),
    ]


def _sre_minority_on_billing_db(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Two on-call SREs among six holders of the billing database.

    Billing Engineering owns it; SRE holds it to run it. Each SRE sees one
    colleague from their own department among five other holders -- a
    minority, not an absence. "Nobody like you holds this" is false here.
    """
    out = [b.resource("billing_db", "Billing DB", "database", "high")]
    holders = tuple((f"billing_eng_{i}", "Billing Engineering") for i in range(4)) + (
        ("sre_oncall_0", "Site Reliability"),
        ("sre_oncall_1", "Site Reliability"),
    )
    for who, dept in holders:
        out.append(b.identity(who, who.replace("_", " ").title(), "human", dept))
        out.append(b.grant(f"g_{who}_billing", who, "billing_db", "read", granted_at=b.ago(days=400)))
        for day in range(0, 28, 4):
            out.append(
                b.event(
                    f"e_{who}_billing_{day}", who, "billing_db", "read",
                    b.ago(days=day, hours=rng.randrange(0, 8)),
                )
            )
    return out


def _key_rotation_job_short_history(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A half-yearly key-rotation job with only three runs on record, 150 days in."""
    return _scheduled_job(
        b,
        "svc_key_rotation",
        "key-rotation-job",
        "Security Engineering",
        ("key_rotation_ledger", "Key Rotation Ledger"),
        (150, 330, 510),
    )


def _consultant_two_visits(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    Two uses 280 days apart, then 220 days of silence.

    Two data points are not a rhythm. If one gap were enough to establish
    cadence, this identity's "rhythm" would be 280 days and it would never be
    called dormant -- which is how an offboarded consultant keeps access.
    """
    return [
        b.identity("marta", "Marta Novak", "human", "Strategy"),
        b.resource("strategy_decks", "Strategy Decks Repo", "repository", "medium"),
        b.grant("g_marta_decks", "marta", "strategy_decks", "write", granted_at=b.ago(days=600)),
        b.event("e_marta_0", "marta", "strategy_decks", "write", b.ago(days=500)),
        b.event("e_marta_1", "marta", "strategy_decks", "write", b.ago(days=220)),
    ]


def _partially_visible_dormant_admin(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    alice's finding, seen through a source that samples 60% of events.

    Confidence lands near 0.57 -- honestly uncertain, but not a blind spot.
    The case that bounds the reporting floor from above: a floor above ~0.57
    would suppress a finding we have good-enough evidence for.
    """
    partial = EvidenceQuality(
        source_reliability=0.95,
        integrity_authenticity=1.0,
        identity_mapping_confidence=1.0,
        completeness=0.6,
    )
    out = [
        b.identity("yara", "Yara Haddad", "human", "Platform Engineering"),
        b.resource("prod_ledger_cluster", "Production Ledger Cluster", "server", "critical"),
        b.resource("team_wiki", "Team Wiki", "api", "low"),
        b.grant(
            "g_yara_admin", "yara", "prod_ledger_cluster", "admin",
            granted_at=b.ago(days=300), quality=partial,
        ),
    ]
    for day in range(0, 10):
        out.append(
            b.event(f"e_yara_{day}", "yara", "team_wiki", "read", b.ago(days=day), quality=partial)
        )
    return out


def _weekly_report_then_bulk_pull(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A weekly 20-read report for two months, then 130 reads in an hour.

    Between ravi (no history) and a routine ETL job: this identity *does* read
    in bulk, just never at this scale. 6.5x its own busiest hour.
    """
    out = [
        b.identity("sofia", "Sofia Rinaldi", "human", "Finance Analytics"),
        b.resource("revenue_mart", "Revenue Mart", "database", "high"),
        b.grant("g_sofia_mart", "sofia", "revenue_mart", "read", granted_at=b.ago(days=365)),
    ]
    for week in range(8):
        out += _read_burst(
            b, "sofia", "revenue_mart", f"weekly{week}", 20, b.ago(days=8 + 7 * week, hours=10), 45
        )
    out += _read_burst(b, "sofia", "revenue_mart", "pull", 130, b.ago(days=3, hours=15), 50)
    return out


def _etl_volume_growth(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    A nightly job whose volume grew from 60 to 100 reads a night this week.

    Growth, not exfiltration: 1.7x its own busiest hour. A multiplier low
    enough to flag this pages on every successful product launch.
    """
    out = [
        b.identity("svc_growth_etl", "growth-etl", "service", "Data Engineering"),
        b.resource("events_lake", "Events Lake", "database", "high"),
        b.grant(
            "g_svc_growth_etl", "svc_growth_etl", "events_lake", "read", granted_at=b.ago(days=400)
        ),
    ]
    for night in range(0, 27):
        out += _read_burst(
            b, "svc_growth_etl", "events_lake", f"night{night}", 100 if night < 7 else 60,
            b.ago(days=night, hours=21), 40,
        )
    return out


# --------------------------------------------------------------------------
# Retired FRESH v1 (written 2026-09-29 after the rules were frozen, read once,
# then moved to HOLDOUT when calibration cycle 2 began)
#
# Written from real-world situations, with the label stating what is true of
# the situation rather than what any rule is expected to do. Not evaluated
# while being written. Some are expected to be hard; that is the point -- a
# fresh set that only contains cases the author knew the engine would get
# right measures the author, not the engine.
#
# Honest limit: the author had read the rules before writing these, so this is
# "written after freezing" rather than truly blind. A set written by someone
# who has never opened detections.py would be stronger.
# --------------------------------------------------------------------------


def _break_glass_admin_vaulted(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An emergency org-root account: standing admin, never used, by design."""
    return [
        b.identity("breakglass_root", "break-glass-root", "human", "Security Operations"),
        b.resource("org_root_account", "Organisation Root Account", "cloud_account", "critical"),
        b.grant(
            "g_breakglass_root", "breakglass_root", "org_root_account", "admin",
            granted_at=b.ago(days=700),
        ),
    ]


def _contractor_residual_write(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A design contractor whose engagement ended four months ago; write access remains."""
    out = [
        b.identity("kofi", "Kofi Mensah", "human", "External Contractors"),
        b.resource("brand_assets_repo", "Brand Assets Repository", "repository", "medium"),
        b.grant("g_kofi_brand", "kofi", "brand_assets_repo", "write", granted_at=b.ago(days=260)),
    ]
    for day in range(130, 250, 6):
        out.append(b.event(f"e_kofi_{day}", "kofi", "brand_assets_repo", "write", b.ago(days=day)))
    return out


def _ci_pipeline_reads_prod_secrets(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A build pipeline with a long-lived read on the CI secrets vault, used every build."""
    out = [
        b.identity("svc_build_pipeline", "build-pipeline", "service", "Developer Productivity"),
        b.resource("ci_secrets_vault", "CI Secrets Vault", "secret_store", "critical"),
        b.grant(
            "g_svc_build_vault", "svc_build_pipeline", "ci_secrets_vault", "read",
            granted_at=b.ago(days=540),
        ),
    ]
    for day in range(0, 14):
        for k in range(3):
            out.append(
                b.event(
                    f"e_svc_build_{day}_{k}", "svc_build_pipeline", "ci_secrets_vault", "read",
                    b.ago(days=day, hours=2 + 5 * k, minutes=rng.randrange(0, 60)),
                )
            )
    return out


def _helpdesk_jit_identity_admin(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A service-desk engineer who elevates to directory admin weekly, just-in-time."""
    out = [
        b.identity("maya", "Maya Okafor", "human", "IT Service Desk"),
        b.resource("workforce_directory", "Workforce Directory", "api", "high"),
        b.grant(
            "g_maya_directory", "maya", "workforce_directory", "manage_identity",
            lifecycle="jit_eligible", granted_at=b.ago(days=400),
        ),
    ]
    for week in range(0, 10):
        out.append(
            b.event(
                f"e_maya_{week}", "maya", "workforce_directory", "grant_permission",
                b.ago(days=week * 7 + 1, hours=rng.randrange(0, 8)),
            )
        )
    return out


def _analyst_access_creep(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A RevOps analyst who picked up a grant every six weeks for most of a year."""
    out = [b.identity("dana", "Dana Whitfield", "human", "Revenue Operations")]
    catalog = (
        ("crm_reports", "CRM Reports", "api", "low", "read", 280),
        ("pipeline_db", "Sales Pipeline DB", "database", "medium", "write", 240),
        ("forecast_models", "Forecast Models Repo", "repository", "medium", "write", 200),
        ("finance_actuals", "Finance Actuals Mart", "database", "high", "read", 150),
        ("board_pack_drafts", "Board Pack Drafts", "repository", "high", "write", 100),
        ("comp_planning", "Compensation Planning", "database", "high", "read", 60),
    )
    for res_id, name, rtype, sens, action, days in catalog:
        out.append(b.resource(res_id, name, rtype, sens))
        out.append(
            b.grant(f"g_dana_{res_id}", "dana", res_id, action, granted_at=b.ago(days=days))
        )
    for day in range(0, 30, 2):
        out.append(b.event(f"e_dana_crm_{day}", "dana", "crm_reports", "read", b.ago(days=day)))
        out.append(
            b.event(f"e_dana_pipe_{day}", "dana", "pipeline_db", "write", b.ago(days=day, hours=3))
        )
    return out


def _resignation_bulk_download(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A salesperson who reads a few accounts a day, then pulls 150 in under an hour."""
    out = [
        b.identity("leo", "Leo Brennan", "human", "Sales"),
        b.resource("crm_accounts_db", "CRM Accounts DB", "database", "high"),
        b.grant("g_leo_crm", "leo", "crm_accounts_db", "read", granted_at=b.ago(days=600)),
    ]
    for day in range(2, 47):
        for k in range(rng.randrange(3, 5)):
            out.append(
                b.event(
                    f"e_leo_{day}_{k}", "leo", "crm_accounts_db", "read",
                    b.ago(days=day, hours=8 - 2 * k, minutes=rng.randrange(0, 60)),
                )
            )
    out += _read_burst(b, "leo", "crm_accounts_db", "exit", 150, b.ago(days=1, hours=6), 50)
    return out


def _annual_compliance_export(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A yearly regulatory filing job, three years of history, 200 days into its year."""
    return _scheduled_job(
        b,
        "svc_annual_filing",
        "annual-filing-export",
        "Legal",
        ("regulatory_filings_db", "Regulatory Filings DB"),
        (200, 565, 930),
    )


def _hr_member_on_deploy_pipeline(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A People Ops employee with standing write on the production deploy pipeline."""
    out = [
        b.identity("zoe", "Zoe Adeyemi", "human", "People Operations"),
        b.resource("prod_deploy_pipeline", "Production Deploy Pipeline", "cloud_account", "high"),
        b.grant("g_zoe_deploy", "zoe", "prod_deploy_pipeline", "write", granted_at=b.ago(days=210)),
        b.event("e_zoe_push", "zoe", "prod_deploy_pipeline", "write", b.ago(days=20)),
    ]
    for i in range(5):
        who = f"platform_eng_{i}"
        out.append(b.identity(who, f"Platform Engineer {i}", "human", "Platform Engineering"))
        out.append(
            b.grant(
                f"g_{who}_deploy", who, "prod_deploy_pipeline", "deploy",
                lifecycle="jit_eligible", granted_at=b.ago(days=365),
            )
        )
        for day in range(0, 20, 4):
            out.append(
                b.event(
                    f"e_{who}_{day}", who, "prod_deploy_pipeline", "write",
                    b.ago(days=day, hours=rng.randrange(0, 8)),
                )
            )
    return out


def _internal_auditor_on_finance_ledger(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """
    An internal auditor with standing read on the general ledger.

    Auditors reading finance systems is the job. His department is a minority
    of the ledger's holders, but not absent: a second auditor holds the same.
    """
    out = []
    holders = (
        ("ahmed", "Ahmed Karimi", "Internal Audit"),
        ("audit_colleague", "Second Internal Auditor", "Internal Audit"),
    ) + tuple((f"gl_ops_{i}", f"GL Accountant {i}", "Finance") for i in range(4))
    out.append(b.resource("gl_ledger", "General Ledger", "database", "critical"))
    for who, name, dept in holders:
        out.append(b.identity(who, name, "human", dept))
        out.append(b.grant(f"g_{who}_gl", who, "gl_ledger", "read", granted_at=b.ago(days=500)))
        for day in range(0, 60, 10):
            out.append(
                b.event(
                    f"e_{who}_gl_{day}", who, "gl_ledger", "read",
                    b.ago(days=day, hours=rng.randrange(0, 8)),
                )
            )
    return out


def _public_admin_api_service(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A gateway service holding standing admin on an internet-facing partner API."""
    out = [
        b.identity("svc_partner_gateway", "partner-gateway", "service", "Integrations"),
        b.resource(
            "partner_api", "Partner Orders API", "api", "critical", exposure="public"
        ),
        b.grant(
            "g_svc_partner_api", "svc_partner_gateway", "partner_api", "admin",
            granted_at=b.ago(days=320),
        ),
    ]
    for day in range(0, 10):
        out.append(
            b.event(f"e_svc_partner_{day}", "svc_partner_gateway", "partner_api", "write",
                    b.ago(days=day, hours=rng.randrange(0, 12)))
        )
    return out


def _external_auditor_public_docs(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An external audit firm's principal reading the public trust-centre documents."""
    out = [
        b.identity(
            "ext_audit_firm", "external-audit-firm", "human", "External Partners", is_external=True
        ),
        b.resource("trust_center_docs", "Trust Center Docs", "api", "low", exposure="public"),
        b.grant("g_ext_audit_docs", "ext_audit_firm", "trust_center_docs", "read",
                granted_at=b.ago(days=90)),
    ]
    for day in range(0, 30, 5):
        out.append(
            b.event(f"e_ext_audit_{day}", "ext_audit_firm", "trust_center_docs", "read",
                    b.ago(days=day))
        )
    return out


def _password_spray_then_role_assumption(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Nine failed logins in fifteen minutes, then success, then an admin role assumed."""
    out = [
        b.identity("irene", "Irene Castillo", "human", "Finance"),
        b.resource("sso_portal", "SSO Portal", "api", "medium"),
        b.resource("finance_admin_role", "Finance Admin Role", "cloud_account", "high"),
        b.grant("g_irene_sso", "irene", "sso_portal", "authenticate", granted_at=b.ago(days=700)),
        b.grant(
            "g_irene_role", "irene", "finance_admin_role", "impersonate",
            lifecycle="jit_eligible", granted_at=b.ago(days=300),
        ),
    ]
    for day in range(3, 33):
        out.append(b.event(f"e_irene_login_{day}", "irene", "sso_portal", "login",
                           b.ago(days=day, hours=15)))
    for i in range(9):
        out.append(
            b.event(f"e_irene_fail_{i}", "irene", "sso_portal", "login",
                    b.ago(hours=30, minutes=-i * 100 // 60), success=False)
        )
    out.append(b.event("e_irene_ok", "irene", "sso_portal", "login", b.ago(hours=29, minutes=40)))
    out.append(
        b.event("e_irene_assume", "irene", "finance_admin_role", "assume_role", b.ago(hours=29))
    )
    return out


def _month_end_close_reads(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A finance analyst whose month-end close is 70 ledger reads an hour, every month."""
    out = [
        b.identity("wei", "Wei Zhang", "human", "Finance"),
        b.resource("subledger_db", "Sub-ledger DB", "database", "high"),
        b.grant("g_wei_subledger", "wei", "subledger_db", "read", granted_at=b.ago(days=800)),
    ]
    for month, day in enumerate((3, 33, 64, 94)):
        out += _read_burst(b, "wei", "subledger_db", f"close{month}", 70, b.ago(days=day, hours=4), 55)
    for day in range(0, 100, 4):
        out.append(b.event(f"e_wei_{day}", "wei", "subledger_db", "read", b.ago(days=day, hours=9)))
    return out


def _terraform_runner_org_wide(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An infrastructure-as-code runner with standing admin across five accounts, all in use."""
    out = [b.identity("svc_iac_runner", "iac-runner", "service", "Cloud Platform")]
    catalog = (
        ("net_account", "Network Account", "high"),
        ("shared_services", "Shared Services Account", "medium"),
        ("prod_data_account", "Production Data Account", "critical"),
        ("prod_app_account", "Production App Account", "critical"),
        ("logging_account", "Logging Account", "high"),
    )
    for res_id, name, sens in catalog:
        out.append(b.resource(res_id, name, "cloud_account", sens))
        out.append(
            b.grant(f"g_iac_{res_id}", "svc_iac_runner", res_id, "admin", granted_at=b.ago(days=450))
        )
        for day in range(0, 14, 2):
            out.append(
                b.event(f"e_iac_{res_id}_{day}", "svc_iac_runner", res_id, "write",
                        b.ago(days=day, hours=rng.randrange(0, 20)))
            )
    return out


# --------------------------------------------------------------------------
# FRESH v2 (written 2026-09-29, after calibration cycle 2 froze the rules)
#
# Same discipline as v1: real-world situations, labels state the truth of the
# situation, nothing scored while writing, read once. New domains throughout,
# so none of these is a re-skin of a case the rules were tuned on. Same honest
# limit: written by someone who had read the rules.
# --------------------------------------------------------------------------


def _v2_shared_service_credential(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A reporting service account whose key three analysts log in with."""
    out = [
        b.identity("svc_kpi_export", "kpi-export", "service", "Business Intelligence"),
        b.resource("kpi_warehouse", "KPI Warehouse", "database", "medium"),
        b.grant("g_svc_kpi", "svc_kpi_export", "kpi_warehouse", "read", granted_at=b.ago(days=300)),
    ]
    for i in range(6):
        out.append(b.event(f"e_svc_kpi_login_{i}", "svc_kpi_export", "kpi_warehouse", "login",
                           b.ago(days=i * 4, hours=-10)))
    return out


def _v2_idle_admin_on_crm(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A sales-ops lead, busy in the CRM daily, who has never used her admin grant on it."""
    out = [
        b.identity("rita", "Rita Solberg", "human", "Sales Operations"),
        b.resource("crm_core", "CRM Core", "api", "high"),
        b.grant("g_rita_admin", "rita", "crm_core", "admin", granted_at=b.ago(days=380)),
    ]
    for day in range(0, 20):
        out.append(b.event(f"e_rita_{day}", "rita", "crm_core", "read", b.ago(days=day, hours=11)))
    return out


def _v2_break_glass_annual_drill(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A tagged break-glass account last exercised in an annual recovery drill."""
    return [
        b.identity("breakglass_dr", "break-glass-dr", "human", "Security Operations",
                   is_break_glass=True),
        b.resource("dr_control_plane", "DR Control Plane", "cloud_account", "critical"),
        b.grant("g_breakglass_dr", "breakglass_dr", "dr_control_plane", "admin",
                granted_at=b.ago(days=900)),
        b.event("e_breakglass_dr_drill", "breakglass_dr", "dr_control_plane", "assume_role",
                b.ago(days=200)),
    ]


def _v2_quarterly_job_running_late(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A quarterly tax-provision job that is two weeks late this quarter."""
    return _scheduled_job(
        b, "svc_tax_provision", "tax-provision-job", "Tax",
        ("tax_provision_db", "Tax Provision DB"), (105, 196, 287, 378, 469),
    )


def _v2_quarter_end_board_pull(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An FP&A analyst who pulls ~200 records at every quarter end; this one is 220."""
    out = [
        b.identity("nils", "Nils Berg", "human", "FP&A"),
        b.resource("planning_cube", "Planning Cube", "database", "high"),
        b.grant("g_nils_cube", "nils", "planning_cube", "read", granted_at=b.ago(days=700)),
    ]
    for q, (day, count) in enumerate(((3, 220), (94, 200), (185, 190), (276, 205))):
        out += _read_burst(b, "nils", "planning_cube", f"q{q}", count, b.ago(days=day, hours=14), 50)
    for day in range(5, 280, 9):
        out.append(b.event(f"e_nils_{day}", "nils", "planning_cube", "read", b.ago(days=day, hours=9)))
    return out


def _v2_new_integration_initial_sync(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A support-desk integration connected three days ago, doing its initial backfill."""
    out = [
        b.identity("svc_helpdesk_sync", "helpdesk-sync", "service", "Customer Support"),
        b.resource("customer_contacts", "Customer Contacts DB", "database", "high"),
        b.grant("g_svc_helpdesk_sync", "svc_helpdesk_sync", "customer_contacts", "read",
                granted_at=b.ago(days=3)),
    ]
    out += _read_burst(b, "svc_helpdesk_sync", "customer_contacts", "backfill", 60,
                       b.ago(days=2, hours=4), 50)
    return out


def _v2_engineer_exit_repo_clone(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An engineer who reads a handful of repo files a day, then 300 in 45 minutes."""
    out = [
        b.identity("aaron", "Aaron Fischer", "human", "Payments Engineering"),
        b.resource("payments_source", "Payments Source Repo", "repository", "high"),
        b.grant("g_aaron_repo", "aaron", "payments_source", "read", granted_at=b.ago(days=900)),
    ]
    for day in range(2, 60):
        for k in range(5):
            out.append(b.event(f"e_aaron_{day}_{k}", "aaron", "payments_source", "read",
                               b.ago(days=day, hours=9 - k)))
    out += _read_burst(b, "aaron", "payments_source", "clone", 300, b.ago(days=1, hours=20), 45)
    return out


def _holders(
    b: EvidenceBuilder, rng: random.Random, res_id: str, holders: tuple[tuple[str, str], ...]
) -> list[Evidence]:
    """Several humans with standing read on one resource, each using it weekly."""
    out: list[Evidence] = []
    for who, dept in holders:
        out.append(b.identity(who, who.replace("_", " ").title(), "human", dept))
        out.append(b.grant(f"g_{who}_{res_id}", who, res_id, "read", granted_at=b.ago(days=300)))
        for day in range(0, 28, 7):
            out.append(b.event(f"e_{who}_{res_id}_{day}", who, res_id, "read",
                               b.ago(days=day, hours=rng.randrange(0, 8))))
    return out


def _v2_marketing_intern_on_hr_db(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A marketing intern with standing read on the HR records DB, alongside five HR staff."""
    out = [b.resource("hr_records", "HR Records DB", "database", "high")]
    out += _holders(b, rng, "hr_records",
                    tuple((f"hr_staff_{i}", "People Operations") for i in range(5))
                    + (("mkt_intern", "Marketing"),))
    return out


def _v2_finance_member_on_ap_db(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An accounts-payable clerk on the AP database, like most of its holders."""
    out = [b.resource("ap_ledger", "Accounts Payable Ledger", "database", "high")]
    out += _holders(b, rng, "ap_ledger",
                    tuple((f"ap_clerk_{i}", "Finance") for i in range(5))
                    + (("treasury_analyst", "Treasury"),))
    return out


def _v2_agent_jit_secret_reader(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An AI agent that requests read on the deployment vault just-in-time."""
    out = [
        b.identity("agent_deployer", "deploy-agent", "ai_agent", "Platform Engineering"),
        b.resource("deploy_vault", "Deployment Vault", "secret_store", "critical"),
        b.grant("g_agent_deployer_vault", "agent_deployer", "deploy_vault", "read",
                lifecycle="jit_eligible", granted_at=b.ago(days=120)),
    ]
    for day in range(0, 14, 2):
        out.append(b.event(f"e_agent_deployer_{day}", "agent_deployer", "deploy_vault", "read",
                           b.ago(days=day, hours=3)))
    return out


def _v2_ml_pipeline_creep(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An ML training service that gained a data grant every couple of months."""
    out = [b.identity("svc_ml_train", "ml-train", "service", "Machine Learning")]
    catalog = (
        ("feature_store", "Feature Store", "medium", 240),
        ("clickstream", "Clickstream Lake", "medium", 180),
        ("support_transcripts", "Support Transcripts", "high", 120),
        ("payments_history", "Payments History", "critical", 70),
        ("hr_attrition", "HR Attrition Data", "high", 30),
    )
    for res_id, name, sens, days in catalog:
        out.append(b.resource(res_id, name, "database", sens))
        out.append(b.grant(f"g_ml_{res_id}", "svc_ml_train", res_id, "read",
                           granted_at=b.ago(days=days)))
    for day in range(0, 20, 2):
        out.append(b.event(f"e_ml_{day}", "svc_ml_train", "feature_store", "read",
                           b.ago(days=day, hours=2)))
    return out


def _v2_public_bucket_admin_medium(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Admin on a public bucket of product screenshots and press kits."""
    out = [
        b.identity("pia", "Pia Laurent", "human", "Communications"),
        b.resource("press_assets", "Press Assets Bucket", "cloud_account", "medium", exposure="public"),
        b.grant("g_pia_press", "pia", "press_assets", "admin", granted_at=b.ago(days=200)),
    ]
    for day in range(0, 30, 3):
        out.append(b.event(f"e_pia_{day}", "pia", "press_assets", "write", b.ago(days=day)))
    return out


def _v2_partner_write_on_claims(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """A logistics partner's principal with standing write on the shipments DB."""
    out = [
        b.identity("partner_logistics", "logistics-partner", "service", "External Partners",
                   is_external=True),
        b.resource("shipments_db", "Shipments DB", "database", "critical"),
        b.grant("g_partner_shipments", "partner_logistics", "shipments_db", "write",
                granted_at=b.ago(days=410)),
    ]
    for day in range(0, 12, 2):
        out.append(b.event(f"e_partner_ship_{day}", "partner_logistics", "shipments_db", "write",
                           b.ago(days=day)))
    return out


def _v2_login_burst_then_self_grant(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """Fourteen failed logins in ten minutes on an admin console, then a self-grant."""
    out = [
        b.identity("owen", "Owen Price", "human", "IT Operations"),
        b.resource("admin_console", "Admin Console", "api", "high"),
        b.grant("g_owen_console", "owen", "admin_console", "manage_permission",
                lifecycle="jit_eligible", granted_at=b.ago(days=250)),
    ]
    for i in range(14):
        out.append(b.event(f"e_owen_fail_{i}", "owen", "admin_console", "login",
                           b.ago(hours=50, minutes=-(i * 10 // 14)), success=False))
    out.append(b.event("e_owen_ok", "owen", "admin_console", "login", b.ago(hours=49, minutes=45)))
    out.append(b.event("e_owen_grant", "owen", "admin_console", "grant_permission",
                       b.ago(hours=49, minutes=30)))
    return out


def _v2_integration_hub_wide_write(b: EvidenceBuilder, rng: random.Random) -> list[Evidence]:
    """An integration hub with standing write to six systems, all genuinely used."""
    out = [b.identity("svc_integration_hub", "integration-hub", "service", "Integrations")]
    catalog = (
        ("erp_orders", "high"), ("warehouse_mgmt", "medium"), ("billing_core", "critical"),
        ("crm_sync", "medium"), ("tax_engine", "high"), ("notify_api", "low"),
    )
    for res_id, sens in catalog:
        out.append(b.resource(res_id, res_id.replace("_", " ").title(), "api", sens))
        out.append(b.grant(f"g_hub_{res_id}", "svc_integration_hub", res_id, "write",
                           granted_at=b.ago(days=330)))
        for day in range(0, 10, 2):
            out.append(b.event(f"e_hub_{res_id}_{day}", "svc_integration_hub", res_id, "write",
                               b.ago(days=day, hours=rng.randrange(0, 20))))
    return out


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="dormant_standing_admin",
        description="Standing admin on a critical database, unused for well over a year.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS", "alice", "Grant g_alice_admin has never been exercised."
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE", "alice", "Standing admin on a CRITICAL resource."
            ),
        ),
        build=_dormant_standing_admin,
    ),
    Scenario(
        name="active_admin_justified",
        description="Negative control: standing admin exercised almost daily.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "bob",
                "Grant is in continuous use; a staleness rule must not fire here.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "bob",
                "Continuous use justifies the need, not the *standing* shape of "
                "the grant. Admin on a crown jewel that is genuinely required is "
                "the textbook JIT candidate: remediation here is elevation with "
                "approval, not revocation. Only the staleness claim is wrong.",
            ),
        ),
        build=_active_admin_justified,
    ),
    Scenario(
        name="admin_on_medium_internal_tool",
        description="Negative control: bob's grant shape on a MEDIUM staging cluster.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "ines",
                "Same grant as bob (standing admin, 300 days, used near-daily); "
                "only the resource differs, MEDIUM instead of CRITICAL. Firing "
                "here means the sensitivity line has drifted down to MEDIUM, and "
                "every engineer with admin on a staging box becomes an alert.",
                should_fire=False,
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "ines",
                "The grant is exercised near-daily.",
                should_fire=False,
            ),
        ),
        build=_admin_on_medium_internal_tool,
    ),
    Scenario(
        name="admin_on_high_internal_service",
        description="bob's grant shape on a HIGH internal gateway.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "hugo",
                "Standing admin on a HIGH resource. Continuous use justifies "
                "the need, not the standing shape: whoever needs admin here "
                "should request it just-in-time.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "hugo",
                "The grant is exercised near-daily.",
                should_fire=False,
            ),
        ),
        build=_admin_on_high_internal_service,
    ),
    Scenario(
        name="burst_then_escalation",
        description="Failed-auth burst on a service account followed by a self-grant.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR", "svc_deploy", "12 failed logins inside 40 minutes."
            ),
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "svc_deploy",
                "grant_permission succeeded minutes after the burst.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_deploy",
                "Standing deploy on the IAM control plane, which is what made "
                "the escalation worth attempting.",
            ),
        ),
        build=_burst_then_escalation,
    ),
    Scenario(
        name="stale_connector_blind_spot",
        description="Connector silently stopped 14 days ago; quiet is not the same as safe.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "carol",
                "Apparent inactivity is a collection gap, so any finding must be "
                "low-confidence rather than low-risk.",
                should_fire=False,
            ),
        ),
        build=_stale_connector_blind_spot,
    ),
    Scenario(
        name="agent_broad_unused_access",
        description="AI agent holding standing write on four resources, exercising one.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "agent_triage",
                "Standing write across four resources including a CRITICAL PII store.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "agent_triage", "Three of four grants never exercised."
            ),
        ),
        build=_agent_broad_unused_access,
    ),
    Scenario(
        name="expired_grant_never_revoked",
        description="A time-bound grant whose expiry passed 60 days ago is still attached.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "dmitri",
                "Grant expired 60 days ago and was never actually removed.",
            ),
        ),
        build=_expired_grant_never_revoked,
        split=HOLDOUT,
    ),
    Scenario(
        name="jit_eligible_unused",
        description="Negative control: an unused JIT-eligible grant is the goal, not a defect.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "elena",
                "A never-exercised JIT grant is a remediated grant. Firing here "
                "penalises exactly the outcome the product exists to produce.",
                should_fire=False,
            ),
        ),
        build=_jit_eligible_unused,
    ),
    Scenario(
        name="departed_contractor_active_grants",
        description="Six months of total silence with access fully intact.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS", "frank", "No activity of any kind for 190 days."
            ),
            # No EXCESSIVE_PRIVILEGE label, deliberately. One existed until
            # 2026-09-29 and was removed on review: frank holds read on a HIGH
            # resource and write on a MEDIUM one, neither privileged, both the
            # right size for the job he had. What is wrong is that he left,
            # which is a staleness fact STALE_ACCESS already reports -- the
            # second label counted one root cause twice. Nor is it flipped to
            # a negative: asserting a departed contractor's access to customer
            # records "must not" be flagged would overclaim.
        ),
        build=_departed_contractor_active_grants,
    ),
    Scenario(
        name="recently_granted_not_yet_used",
        description="Negative control: granted two days ago, not yet exercised.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "grace",
                "Feature-identical to alice (standing admin, CRITICAL resource, "
                "no privileged use) except the grant is 2 days old, not 420.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "grace",
                "Standing admin on a CRITICAL resource is worth surfacing even "
                "on day two; it is the staleness claim that would be wrong.",
            ),
        ),
        build=_recently_granted_not_yet_used,
    ),
    Scenario(
        name="seasonal_quarterly_batch",
        description="Negative control: a service account that legitimately runs quarterly.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_quarterly_close",
                "85 days idle is this identity's normal cadence; four prior runs "
                "establish it. A fixed global threshold cannot express that.",
                should_fire=False,
            ),
        ),
        build=_seasonal_quarterly_batch,
        split=HOLDOUT,
    ),
    Scenario(
        name="admin_on_low_sensitivity_sandbox",
        description="Negative control: standing admin over a throwaway sandbox.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "henry",
                "admin is only alarming in proportion to what it is admin over.",
                should_fire=False,
            ),
        ),
        build=_admin_on_low_sensitivity_sandbox,
        split=HOLDOUT,
    ),
    Scenario(
        name="read_only_analyst_wide_access",
        description="Negative control: six grants, all read, all low value.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "iris",
                "Breadth without depth is not blast radius; counting grants "
                "unweighted flags the whole analytics org.",
                should_fire=False,
            ),
        ),
        build=_read_only_analyst_wide_access,
    ),
    Scenario(
        name="delete_on_critical_never_used",
        description="Standing delete on a crown-jewel archive, never exercised.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "julia",
                "Standing delete on a CRITICAL resource is pure downside.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "julia", "The delete grant has never been used."
            ),
        ),
        build=_delete_on_critical_never_used,
        split=HOLDOUT,
    ),
    Scenario(
        name="service_account_sprawl",
        description="A CI account holding standing admin on six resources, two critical.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "svc_ci_runner",
                "Standing admin across six resources including production and payments.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_ci_runner",
                "Five of six grants are never exercised; it only builds.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_ci_runner",
                "Standing admin on production Kubernetes and the payments gateway.",
            ),
        ),
        build=_service_account_sprawl,
    ),
    Scenario(
        name="agent_scope_accretion",
        description="An AI agent whose scope grew by one grant a month for five months.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "agent_ops",
                "Five standing write grants ending at a CRITICAL replica.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "agent_ops",
                "Privilege creep: one grant a month for five months, none ever "
                "revoked or reviewed, ending at a CRITICAL replica. No single "
                "grant is excessive; the accumulation is. A known miss -- no "
                "rule reads grant cadence yet.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "agent_ops",
                "Four of five grants have never been exercised; it only reads alerts.",
            ),
        ),
        build=_agent_scope_accretion,
    ),
    Scenario(
        name="revoke_then_regrant",
        description="A revoke followed four minutes later by a re-grant.",
        expected=(
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "svc_automation",
                "Revoke-then-regrant within minutes is the shape of covering tracks.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_automation",
                "Standing admin on the corporate directory.",
            ),
        ),
        build=_revoke_then_regrant,
    ),
    Scenario(
        name="assume_role_chain",
        description="Four assume_role hops in nine minutes, ending at an HSM vault.",
        expected=(
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "kwame",
                "Each hop is authorised; the chain terminating at a CRITICAL "
                "vault is the finding.",
            ),
        ),
        build=_assume_role_chain,
        split=HOLDOUT,
    ),
    Scenario(
        name="legitimate_onboarding_grants",
        description="Negative control: an IT admin issuing six grants in one afternoon.",
        expected=(
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "laura",
                "Identical event shape to an escalation burst, but it is routine "
                "onboarding backed by two years of the same behaviour.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "laura",
                "Her use of permission-management rights is legitimate; holding "
                "them *standing* still is not. Same reasoning as bob: the "
                "remediation is approval-gated elevation, not revocation.",
            ),
        ),
        build=_legitimate_onboarding_grants,
        split=HOLDOUT,
    ),
    Scenario(
        name="credential_stuffing_no_success",
        description="Thirty failed logins in half an hour, none successful.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "svc_legacy_sync",
                "30 failed logins inside 30 minutes.",
            ),
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "svc_legacy_sync",
                "Nothing succeeded. Treating a blocked attack as a takeover "
                "manufactures an incident out of a working control.",
                should_fire=False,
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_legacy_sync",
                "Every authentication attempt on record has failed, so this grant "
                "has never once been successfully exercised.",
            ),
        ),
        build=_credential_stuffing_no_success,
    ),
    Scenario(
        name="failed_logins_spread_thin",
        description="Negative control: twelve failed logins spread over thirty days.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "marcus",
                "Same failed_authentication_count as burst_then_escalation (12), "
                "but a rate of 0.4/day rather than 18/hour, each followed by a "
                "successful login. Count-based rules cannot tell these apart.",
                should_fire=False,
            ),
        ),
        build=_failed_logins_spread_thin,
    ),
    Scenario(
        name="mass_delete_burst",
        description="Forty deletes against a critical audit archive inside two hours.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "svc_retention",
                "40 destructive actions in 2 hours against a CRITICAL resource.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_retention",
                "Standing delete on a CRITICAL audit archive.",
            ),
        ),
        build=_mass_delete_burst,
        split=HOLDOUT,
    ),
    Scenario(
        name="dormant_then_sudden_activity",
        description="Four months silent, then thirty actions in one afternoon.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "nadia",
                "Neither dormancy nor a busy day is suspicious; the transition is.",
            ),
        ),
        build=_dormant_then_sudden_activity,
    ),
    Scenario(
        name="department_context_mismatch",
        description="A Marketing employee with standing admin on the payments ledger.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "oscar",
                "Marketing has no business relationship with a payments database.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "oscar",
                "Standing admin on a CRITICAL resource.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "oscar",
                "He reads the ledger but has never used the admin rights he holds "
                "over it -- the admin grant is dead weight on a crown jewel.",
            ),
        ),
        build=_department_context_mismatch,
    ),
    Scenario(
        name="service_account_interactive_login",
        description="A service identity performing repeated interactive logins.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "svc_reporting",
                "Service accounts authenticate with keys; successful interactive "
                "logins mean a human is wearing the credential.",
            ),
        ),
        build=_service_account_interactive_login,
        split=HOLDOUT,
    ),
    Scenario(
        name="incomplete_but_fresh_collection",
        description="A healthy connector with only partial visibility: fresh, but half-blind.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "priya",
                "collected_at is current, so no lag-based check fires -- but "
                "completeness is 0.5 and identity mapping 0.6. Confidence must "
                "be suppressed on quality grounds, not freshness grounds.",
                should_fire=False,
            ),
        ),
        build=_incomplete_but_fresh_collection,
        split=HOLDOUT,
    ),
    Scenario(
        name="public_bucket_standing_write",
        description="Standing admin on an internet-facing bucket of customer exports.",
        expected=(
            ExpectedFinding(
                "EXTERNAL_EXPOSURE",
                "quentin",
                "Standing admin on a CRITICAL resource that is reachable from "
                "the public internet.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "quentin",
                "Standing admin on a CRITICAL resource.",
            ),
        ),
        build=_public_bucket_standing_write,
    ),
    Scenario(
        name="public_by_design_marketing_site",
        description="Negative control: resources that are public because they must be.",
        expected=(
            ExpectedFinding(
                "EXTERNAL_EXPOSURE",
                "rosa",
                "Both resources are PUBLIC and both are LOW sensitivity. Firing "
                "on exposure alone flags every CDN and status page in the estate.",
                should_fire=False,
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "rosa",
                "The status-page grant is 300 days old and has never been used. "
                "Public-by-design excuses the exposure, not the dormancy.",
            ),
        ),
        build=_public_by_design_marketing_site,
    ),
    Scenario(
        name="external_partner_critical_access",
        description="An external partner principal holding standing write on a critical DB.",
        expected=(
            ExpectedFinding(
                "EXTERNAL_EXPOSURE",
                "partner_integrator",
                "The resource is internal, so resource-side checks read clean. "
                "The exposure is the principal: a partner outside our IdP.",
            ),
        ),
        build=_external_partner_critical_access,
        split=HOLDOUT,
    ),
    Scenario(
        name="finance_admin_on_finance_db",
        description="Negative control: standing admin that fits the holder exactly.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "sonia",
                "Same grant shape as oscar (standing admin, CRITICAL finance DB, "
                "actively used); only the department attribute differs.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "sonia",
                "Standing admin on a CRITICAL resource is still worth raising "
                "even when the holder is the right person for it.",
            ),
        ),
        build=_finance_admin_on_finance_db,
    ),
    Scenario(
        name="dormant_permission_manager",
        description="Standing permission-management rights on a critical IAM control plane.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "viktor",
                "Standing manage_permission: this identity can grant itself "
                "every other capability, which makes every other control advisory.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "viktor",
                "He reads the control plane but has never exercised the "
                "permission-management rights he holds over it.",
            ),
        ),
        build=_dormant_permission_manager,
    ),
    Scenario(
        name="jit_permission_manager",
        description="Negative control: the same capability, held JIT-eligible and used.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "wendy",
                "Same capability as viktor on an equally critical resource; only "
                "the lifecycle differs. This is what remediating viktor looks "
                "like, and firing here reports no improvement after the fix.",
                should_fire=False,
            ),
        ),
        build=_jit_permission_manager,
    ),
    Scenario(
        name="governed_crown_jewel",
        description="Permission management on a MEDIUM tool that governs a CRITICAL ledger.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "gustav",
                "Standing manage_permission over the tool that controls who holds "
                "the treasury ledger: he can grant himself admin on a crown jewel. "
                "The grant's own resource is MEDIUM; the privilege is what it governs.",
            ),
        ),
        build=_governed_crown_jewel,
    ),
    Scenario(
        name="governed_low_value_only",
        description="Negative control: the same grant, on a tool governing only LOW resources.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "hanna",
                "Same grant, same tool tier, same usage as gustav; everything the "
                "tool governs is LOW. Permission management over a wiki is not "
                "the same finding.",
                should_fire=False,
            ),
        ),
        build=_governed_low_value_only,
    ),
    Scenario(
        name="unmapped_capability_grants",
        description="A vendor vocabulary with no mapping: grants retained, confidence suppressed.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "yusuf",
                "Four standing grants on a CRITICAL resource do trip the "
                "blast-radius rule, and the engine must hold it back: three of "
                "the four are Capability.UNKNOWN, so capability_coverage is "
                "0.25 and confidence falls under the floor. Retained (dropping "
                "understates access), reported as a coverage gap rather than "
                "an all-clear.",
                should_fire=False,
            ),
        ),
        build=_unmapped_capability_grants,
        split=HOLDOUT,
    ),    Scenario(
        name="standing_identity_manager",
        description="Standing rights to create principals and reset credentials, unused.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_helpdesk",
                "Standing manage_identity on a CRITICAL directory: it can mint a "
                "principal, entitle it, and act as someone who never touched a "
                "keyboard.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_helpdesk",
                "It reads the directory but has never exercised the "
                "identity-management rights it holds over it.",
            ),
        ),
        build=_standing_identity_manager,
    ),
    Scenario(
        name="scoped_identity_manager",
        description="Negative control: the same capability, time-boxed and in weekly use.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "zainab",
                "Same capability as svc_helpdesk on an equally critical "
                "directory; the grant expires in 9 days and is exercised "
                "weekly. Firing here makes time-boxing indistinguishable from "
                "leaving it standing.",
                should_fire=False,
            ),
        ),
        build=_scoped_identity_manager,
        split=HOLDOUT,
    ),
    Scenario(
        name="security_control_tamper_rights",
        description="Standing rights over the audit pipeline: can switch off its own witness.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_observability",
                "Standing manage_security_control on the audit pipeline: this "
                "identity can stop the logging that would record what it does "
                "next, disabling every other detection from the inside.",
            ),
        ),
        build=_security_control_tamper_rights,
    ),
    Scenario(
        name="security_control_read_only",
        description="Negative control: can watch the monitoring, cannot switch it off.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "tomas",
                "Standing READ on a CRITICAL SIEM. Keying on the resource being "
                "a security control rather than the capability held over it "
                "would page about every SRE on the roster.",
                should_fire=False,
            ),
        ),
        build=_security_control_read_only,
        split=HOLDOUT,
    ),    Scenario(
        name="dormant_cross_account_role",
        description="Standing rights to assume a role into production, never exercised.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "rahul",
                "Standing impersonation into a CRITICAL production account: it "
                "confers nothing directly and everything indirectly.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "rahul",
                "He reads the account but has never assumed the role in 395 days.",
            ),
        ),
        build=_dormant_cross_account_role,
    ),
    # --- Tier 2 training pairs (2026-09-29) --------------------------------
    Scenario(
        name="semiannual_job_on_cadence",
        description="Negative control: a half-yearly job, 120 days into its cycle.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_semiannual_audit",
                "Four runs 182 days apart; 120 days idle is on schedule. A global "
                "90-day threshold calls this dormant twice a year.",
                should_fire=False,
            ),
        ),
        build=_semiannual_job_on_cadence,
    ),
    Scenario(
        name="quarterly_job_missed_runs",
        description="A quarterly job that stopped: last run 160 days ago.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_quarterly_recon",
                "Five runs 91 days apart, then silence through the next scheduled "
                "run. Its own rhythm says it should have run by day 91.",
            ),
        ),
        build=_quarterly_job_missed_runs,
    ),
    Scenario(
        name="onboarding_batch_grants",
        description="Negative control: agent_ops's five grants, issued in one afternoon.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "agent_intake",
                "Same grants as agent_ops, issued together 150 days ago. "
                "Over-provisioning, not creep: nothing accumulated.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "agent_intake",
                "Five standing write grants reaching a CRITICAL replica.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "agent_intake",
                "Four of five grants have never been exercised.",
            ),
        ),
        build=_onboarding_batch_grants,
    ),
    Scenario(
        name="standing_read_on_secret_store",
        description="Standing read on the production vault, used weekly.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "otto",
                "Standing read on a CRITICAL secret store confers every "
                "credential inside it. Secrets should be issued just-in-time.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "otto", "Read weekly.", should_fire=False
            ),
        ),
        build=_standing_read_on_secret_store,
    ),
    Scenario(
        name="standing_read_on_critical_db",
        description="Negative control: otto's grant shape on an ordinary database.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "pablo",
                "Identical to otto but the resource is a database, not a vault. "
                "Standing read on data is not privilege; treating it as such "
                "would flag every analyst (same reasoning as tomas).",
                should_fire=False,
            ),
            ExpectedFinding(
                "STALE_ACCESS", "pablo", "Read weekly.", should_fire=False
            ),
        ),
        build=_standing_read_on_critical_db,
    ),
    Scenario(
        name="bulk_export_after_quiet_history",
        description="Two reads a day for two months, then 80 reads in 40 minutes.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "ravi",
                "80 reads of a CRITICAL customer export inside an hour, against a "
                "history of one or two a day.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "ravi", "Read daily.", should_fire=False
            ),
        ),
        build=_bulk_export_after_quiet_history,
    ),
    Scenario(
        name="nightly_etl_on_schedule",
        description="Negative control: ravi's burst volume, every night for 20 nights.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "svc_nightly_etl",
                "80 reads in 40 minutes is this job's normal night. Volume "
                "without a baseline flags every ETL pipeline in the estate.",
                should_fire=False,
            ),
        ),
        build=_nightly_etl_on_schedule,
    ),
    # --- Calibration cycle 2 training cases (2026-09-29) ---------------------
    Scenario(
        name="emergency_db_break_glass",
        description="A tagged break-glass account: standing admin, never used.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "breakglass_payments",
                "Tagged break-glass by the source of record: never used is "
                "its designed state.",
                should_fire=False,
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "breakglass_payments",
                "The tag excuses the dormancy, never the privilege: standing "
                "admin on a CRITICAL database, reported so it is vaulted and "
                "watched.",
            ),
        ),
        build=_emergency_db_break_glass,
    ),
    Scenario(
        name="sre_minority_on_billing_db",
        description="Two on-call SREs among six holders of the billing DB.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "sre_oncall_0",
                "One of the five other holders shares her department. A "
                "minority, not an absence.",
                should_fire=False,
            ),
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "sre_oncall_1",
                "Same situation as sre_oncall_0.",
                should_fire=False,
            ),
        ),
        build=_sre_minority_on_billing_db,
    ),
    Scenario(
        name="key_rotation_job_short_history",
        description="A half-yearly job with three runs on record, 150 days in.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_key_rotation",
                "Two gaps of 180 days are a schedule; 150 days idle is on it.",
                should_fire=False,
            ),
        ),
        build=_key_rotation_job_short_history,
    ),
    Scenario(
        name="consultant_two_visits",
        description="Two uses 280 days apart, then 220 days of silence.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "marta",
                "Two data points are not a rhythm; 220 days of silence with "
                "standing write is an offboarding gap.",
            ),
        ),
        build=_consultant_two_visits,
    ),
    Scenario(
        name="partially_visible_dormant_admin",
        description="alice's finding through a source that sees 60% of events.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "yara",
                "Unused standing admin on a CRITICAL cluster; evidence is "
                "partial (confidence ~0.57) but good enough to report.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "yara",
                "Standing admin on a CRITICAL resource.",
            ),
        ),
        build=_partially_visible_dormant_admin,
    ),
    Scenario(
        name="weekly_report_then_bulk_pull",
        description="A weekly 20-read report, then 130 reads in an hour.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "sofia",
                "6.5x her own busiest hour on a HIGH revenue mart.",
            ),
        ),
        build=_weekly_report_then_bulk_pull,
    ),
    Scenario(
        name="etl_volume_growth",
        description="Negative control: nightly volume grew from 60 to 100 reads.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "svc_growth_etl",
                "1.7x its own busiest hour: growth, not exfiltration.",
                should_fire=False,
            ),
        ),
        build=_etl_volume_growth,
    ),
    # --- Retired FRESH v1 (read once 2026-09-29) -> HOLDOUT -------------------
    # Spent: its answers are known, and calibration cycle 2's TRAIN traps were
    # shaped by its failures. Kept as contaminated holdout, never re-quoted.
    Scenario(
        name="break_glass_admin_vaulted",
        description="Emergency org-root account: standing admin, never used by design.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "breakglass_root",
                "Standing admin on the organisation root is standing admin, "
                "however well the credential is vaulted.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "breakglass_root",
                "Never used is the designed state of a break-glass account; "
                "the day it is used is the incident. Not stale access.",
                should_fire=False,
            ),
        ),
        build=_break_glass_admin_vaulted,
        split=HOLDOUT,
    ),
    Scenario(
        name="contractor_residual_write",
        description="An ended contractor engagement with write access still attached.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "kofi",
                "Four months of silence after a period of steady work: the "
                "engagement ended and offboarding missed the grant.",
            ),
        ),
        build=_contractor_residual_write,
        split=HOLDOUT,
    ),
    Scenario(
        name="ci_pipeline_reads_prod_secrets",
        description="A build pipeline with standing read on the CI secrets vault.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_build_pipeline",
                "A long-lived read on a CRITICAL vault; workload federation or "
                "short-lived secrets are the fix.",
            ),
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_build_pipeline",
                "Used on every build.",
                should_fire=False,
            ),
        ),
        build=_ci_pipeline_reads_prod_secrets,
        split=HOLDOUT,
    ),
    Scenario(
        name="helpdesk_jit_identity_admin",
        description="Directory admin held JIT-eligible and elevated weekly.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "maya",
                "JIT-eligible is the remediated state.",
                should_fire=False,
            ),
        ),
        build=_helpdesk_jit_identity_admin,
        split=HOLDOUT,
    ),
    Scenario(
        name="analyst_access_creep",
        description="A grant every six weeks for most of a year; two in use.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "dana",
                "Six grants accumulated one at a time, three of them on HIGH "
                "finance data she has never opened.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "dana", "Four of six grants never exercised."
            ),
        ),
        build=_analyst_access_creep,
        split=HOLDOUT,
    ),
    Scenario(
        name="resignation_bulk_download",
        description="A few account reads a day, then 150 in under an hour.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR", "leo", "150 reads in 50 minutes against ~4/day."
            ),
            ExpectedFinding("STALE_ACCESS", "leo", "Read daily.", should_fire=False),
        ),
        build=_resignation_bulk_download,
        split=HOLDOUT,
    ),
    Scenario(
        name="annual_compliance_export",
        description="A yearly filing job, 200 days into its year.",
        expected=(
            ExpectedFinding(
                "STALE_ACCESS",
                "svc_annual_filing",
                "Three years of runs 365 days apart; 200 days idle is on schedule.",
                should_fire=False,
            ),
        ),
        build=_annual_compliance_export,
        split=HOLDOUT,
    ),
    Scenario(
        name="hr_member_on_deploy_pipeline",
        description="People Ops with standing write on the production deploy pipeline.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "zoe",
                "Everyone else who can touch the pipeline is Platform "
                "Engineering, and they hold it JIT.",
            ),
        ),
        build=_hr_member_on_deploy_pipeline,
        split=HOLDOUT,
    ),
    Scenario(
        name="internal_auditor_on_finance_ledger",
        description="An internal auditor with standing read on the general ledger.",
        expected=(
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "ahmed",
                "Auditors reading the ledger is the job, and a second auditor "
                "holds the same access.",
                should_fire=False,
            ),
            # Triaged from an unlabelled firing after the one FRESH reading
            # (2026-09-29). Same situation as ahmed, so the same truth. Adding
            # it lowered fresh precision; it is recorded, not tuned away.
            ExpectedFinding(
                "CONTEXT_MISMATCH",
                "audit_colleague",
                "The second auditor: identical situation to ahmed.",
                should_fire=False,
            ),
        ),
        build=_internal_auditor_on_finance_ledger,
        split=HOLDOUT,
    ),
    Scenario(
        name="public_admin_api_service",
        description="Standing admin on an internet-facing CRITICAL partner API.",
        expected=(
            ExpectedFinding(
                "EXTERNAL_EXPOSURE",
                "svc_partner_gateway",
                "Admin on a CRITICAL resource reachable from the internet.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_partner_gateway",
                "Standing admin on a CRITICAL resource.",
            ),
        ),
        build=_public_admin_api_service,
        split=HOLDOUT,
    ),
    Scenario(
        name="external_auditor_public_docs",
        description="An external principal reading public, low-value documents.",
        expected=(
            ExpectedFinding(
                "EXTERNAL_EXPOSURE",
                "ext_audit_firm",
                "External reader of public LOW documents: nothing is exposed "
                "that was not published on purpose.",
                should_fire=False,
            ),
        ),
        build=_external_auditor_public_docs,
        split=HOLDOUT,
    ),
    Scenario(
        name="password_spray_then_role_assumption",
        description="Failed-login burst, success, then an admin role assumed.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR", "irene", "Nine failed logins in fifteen minutes."
            ),
            ExpectedFinding(
                "PRIVILEGE_ESCALATION",
                "irene",
                "A finance admin role assumed forty minutes after the burst ended.",
            ),
        ),
        build=_password_spray_then_role_assumption,
        split=HOLDOUT,
    ),
    Scenario(
        name="month_end_close_reads",
        description="Month-end close: 70 ledger reads an hour, every month.",
        expected=(
            ExpectedFinding(
                "ANOMALOUS_BEHAVIOR",
                "wei",
                "This month's close looks exactly like the last three.",
                should_fire=False,
            ),
        ),
        build=_month_end_close_reads,
        split=HOLDOUT,
    ),
    Scenario(
        name="terraform_runner_org_wide",
        description="An IaC runner with standing admin on five accounts, all in use.",
        expected=(
            ExpectedFinding(
                "EXCESSIVE_BLAST_RADIUS",
                "svc_iac_runner",
                "One credential reaches two CRITICAL production accounts and three more.",
            ),
            ExpectedFinding(
                "EXCESSIVE_PRIVILEGE",
                "svc_iac_runner",
                "Standing admin on CRITICAL accounts.",
            ),
            ExpectedFinding(
                "STALE_ACCESS", "svc_iac_runner", "Every grant in use.", should_fire=False
            ),
        ),
        build=_terraform_runner_org_wide,
        split=HOLDOUT,
    ),
    # --- FRESH v2 (2026-09-29, after calibration cycle 2 froze the rules) -----
    Scenario(
        name='v2_shared_service_credential',
        description='A service account whose key analysts log in with.',
        expected=(
            ExpectedFinding(
                'CONTEXT_MISMATCH',
                'svc_kpi_export',
                'Six interactive logins on a key-based service identity: people are sharing its credential.',
            ),
        ),
        build=_v2_shared_service_credential,
        split=FRESH,
    ),
    Scenario(
        name='v2_idle_admin_on_crm',
        description='Busy in the CRM daily; admin on it never used.',
        expected=(
            ExpectedFinding(
                'STALE_ACCESS',
                'rita',
                'Admin on the CRM has never been exercised in 380 days; her reads do not use it.',
            ),
            ExpectedFinding(
                'EXCESSIVE_PRIVILEGE',
                'rita',
                'Standing admin on a HIGH system.',
            ),
        ),
        build=_v2_idle_admin_on_crm,
        split=FRESH,
    ),
    Scenario(
        name='v2_break_glass_annual_drill',
        description='Tagged break-glass account, last used in an annual drill.',
        expected=(
            ExpectedFinding(
                'STALE_ACCESS',
                'breakglass_dr',
                'Tagged emergency account; 200 days since the drill is its designed state.',
                should_fire=False,
            ),
            ExpectedFinding(
                'EXCESSIVE_PRIVILEGE',
                'breakglass_dr',
                'Standing admin on the DR control plane is still standing admin.',
            ),
        ),
        build=_v2_break_glass_annual_drill,
        split=FRESH,
    ),
    Scenario(
        name='v2_quarterly_job_running_late',
        description='A quarterly job two weeks late this quarter.',
        expected=(
            ExpectedFinding(
                'STALE_ACCESS',
                'svc_tax_provision',
                'Five runs 91 days apart; 105 days is late, not dormant.',
                should_fire=False,
            ),
        ),
        build=_v2_quarterly_job_running_late,
        split=FRESH,
    ),
    Scenario(
        name='v2_quarter_end_board_pull',
        description='Quarter-end pull of ~200 records, as every quarter.',
        expected=(
            ExpectedFinding(
                'ANOMALOUS_BEHAVIOR',
                'nils',
                '220 records at quarter end against 190-205 at the last three.',
                should_fire=False,
            ),
        ),
        build=_v2_quarter_end_board_pull,
        split=FRESH,
    ),
    Scenario(
        name='v2_new_integration_initial_sync',
        description='A three-day-old integration doing its initial backfill.',
        expected=(
            ExpectedFinding(
                'ANOMALOUS_BEHAVIOR',
                'svc_helpdesk_sync',
                'An initial backfill is what a newly connected integration does.',
                should_fire=False,
            ),
        ),
        build=_v2_new_integration_initial_sync,
        split=FRESH,
    ),
    Scenario(
        name='v2_engineer_exit_repo_clone',
        description='A few repo reads a day, then 300 in 45 minutes.',
        expected=(
            ExpectedFinding(
                'ANOMALOUS_BEHAVIOR',
                'aaron',
                '300 reads of the payments source in 45 minutes against ~5 a day.',
            ),
        ),
        build=_v2_engineer_exit_repo_clone,
        split=FRESH,
    ),
    Scenario(
        name='v2_marketing_intern_on_hr_db',
        description='A marketing intern among HR staff on the HR records DB.',
        expected=(
            ExpectedFinding(
                'CONTEXT_MISMATCH',
                'mkt_intern',
                'Every other holder of HR records is People Operations.',
            ),
        ),
        build=_v2_marketing_intern_on_hr_db,
        split=FRESH,
    ),
    Scenario(
        name='v2_finance_member_on_ap_db',
        description='An AP clerk on the AP ledger, like most of its holders.',
        expected=(
            ExpectedFinding(
                'CONTEXT_MISMATCH',
                'ap_clerk_0',
                'Four of five other holders are Finance.',
                should_fire=False,
            ),
            # Triaged from an unlabelled firing after the one FRESH v2 reading.
            # Treasury and AP sit in the same finance organisation; reading the
            # AP ledger for cash forecasting is the job. A judgement call,
            # recorded as one: it lowered fresh specificity.
            ExpectedFinding(
                'CONTEXT_MISMATCH',
                'treasury_analyst',
                'Treasury reading the AP ledger is adjacent-team work, not a mismatch.',
                should_fire=False,
            ),
        ),
        build=_v2_finance_member_on_ap_db,
        split=FRESH,
    ),
    Scenario(
        name='v2_agent_jit_secret_reader',
        description='An AI agent reading the deployment vault just-in-time.',
        expected=(
            ExpectedFinding(
                'EXCESSIVE_PRIVILEGE',
                'agent_deployer',
                'JIT-eligible secret access is the remediated state.',
                should_fire=False,
            ),
        ),
        build=_v2_agent_jit_secret_reader,
        split=FRESH,
    ),
    Scenario(
        name='v2_ml_pipeline_creep',
        description='An ML service gaining a data grant every couple of months.',
        expected=(
            ExpectedFinding(
                'EXCESSIVE_PRIVILEGE',
                'svc_ml_train',
                'Five grants accumulated over eight months, reaching payments and HR data it never reads.',
            ),
            ExpectedFinding(
                'STALE_ACCESS',
                'svc_ml_train',
                'Four of five grants never exercised.',
            ),
            # Triaged from an unlabelled firing after the one FRESH v2 reading.
            ExpectedFinding(
                'EXCESSIVE_BLAST_RADIUS',
                'svc_ml_train',
                'One credential reaches payments history, HR and support data.',
            ),
        ),
        build=_v2_ml_pipeline_creep,
        split=FRESH,
    ),
    Scenario(
        name='v2_public_bucket_admin_medium',
        description='Admin on a public bucket of press assets.',
        expected=(
            ExpectedFinding(
                'EXTERNAL_EXPOSURE',
                'pia',
                'Public by design and MEDIUM value; nothing sensitive is reachable.',
                should_fire=False,
            ),
        ),
        build=_v2_public_bucket_admin_medium,
        split=FRESH,
    ),
    Scenario(
        name='v2_partner_write_on_claims',
        description='A partner principal with standing write on a CRITICAL DB.',
        expected=(
            ExpectedFinding(
                'EXTERNAL_EXPOSURE',
                'partner_logistics',
                'An identity outside our IdP holds standing write on a CRITICAL database.',
            ),
        ),
        build=_v2_partner_write_on_claims,
        split=FRESH,
    ),
    Scenario(
        name='v2_login_burst_then_self_grant',
        description='Fourteen failed logins, then a successful self-grant.',
        expected=(
            ExpectedFinding(
                'ANOMALOUS_BEHAVIOR',
                'owen',
                'Fourteen failed logins inside ten minutes.',
            ),
            ExpectedFinding(
                'PRIVILEGE_ESCALATION',
                'owen',
                'A permission grant fifteen minutes after the burst ended.',
            ),
        ),
        build=_v2_login_burst_then_self_grant,
        split=FRESH,
    ),
    Scenario(
        name='v2_integration_hub_wide_write',
        description='An integration hub writing to six systems, all used.',
        expected=(
            ExpectedFinding(
                'EXCESSIVE_BLAST_RADIUS',
                'svc_integration_hub',
                'One credential writes to six systems including CRITICAL billing.',
            ),
            ExpectedFinding(
                'STALE_ACCESS',
                'svc_integration_hub',
                'Every grant is exercised.',
                should_fire=False,
            ),
        ),
        build=_v2_integration_hub_wide_write,
        split=FRESH,
    ),
)


def scenarios_for(split: Optional[str] = None) -> tuple[Scenario, ...]:
    """
    The scenarios in one split, or all of them when `split` is None.

    Scenario independence -- already asserted by
    `test_scenarios_are_independent` -- is what makes a split safe: evaluating
    a subset produces exactly the records those scenarios would have produced
    inside the full corpus, so a per-split score is comparable to a full-corpus
    one rather than being an artifact of what got left out.
    """
    if split is None:
        return SCENARIOS
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}, got {split!r}")
    return tuple(s for s in SCENARIOS if s.split == split)


# --------------------------------------------------------------------------
# Connector
# --------------------------------------------------------------------------


class SyntheticConnector:
    """
    Emits scenario evidence plus optional random filler.

    Satisfies EvidenceConnector structurally; nothing here subclasses anything.
    """

    DEPARTMENTS = ("Engineering", "Finance", "Support", "Marketing", "Legal")
    ACTIONS = ("read", "write", "delete", "admin", "deploy")
    SENSITIVITIES = ("low", "medium", "high", "critical")
    RESOURCE_TYPES = ("database", "repository", "cloud_account", "server", "api")

    def __init__(
        self,
        *,
        anchor_time: datetime,
        scenarios: Sequence[Scenario] = SCENARIOS,
        seed: int = 0,
        filler_identities: int = 0,
        source_id: str = "scenario-set-v1",
    ) -> None:
        validate_tz_datetime(anchor_time, "anchor_time")
        if filler_identities < 0:
            raise ValueError("filler_identities must be non-negative")
        self.anchor_time = anchor_time
        self.scenarios = tuple(scenarios)
        self.seed = seed
        self.filler_identities = filler_identities
        self._source = SourceRef(source_type=SourceType.SYNTHETIC, source_id=source_id)

    def source_ref(self) -> SourceRef:
        return self._source

    def expected_findings(self) -> tuple[ExpectedFinding, ...]:
        """Ground truth across the configured scenarios. Used to score detection."""
        return tuple(f for s in self.scenarios for f in s.expected)

    def collect(
        self,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Iterator[Evidence]:
        if since is not None:
            validate_tz_datetime(since, "since")
        if until is not None:
            validate_tz_datetime(until, "until")

        builder = EvidenceBuilder(self._source, self.anchor_time)

        for scenario in self.scenarios:
            # Seeded from the scenario name ALONE -- deliberately not from
            # self.seed. Scenario records are labelled ground truth, so they must
            # not drift when someone turns a knob that exists only to control
            # filler volume; otherwise a "change the seed" experiment silently
            # rewrites the fixtures your detection tests assert against.
            # Keying on the name also keeps scenarios independent: adding or
            # reordering one cannot shift the data produced by any other.
            rng = random.Random(scenario.name)
            for ev in scenario.build(builder, rng):
                if self._in_window(ev, since, until):
                    yield ev

        for ev in self._filler(builder):
            if self._in_window(ev, since, until):
                yield ev

    @staticmethod
    def _in_window(
        ev: Evidence, since: Optional[datetime], until: Optional[datetime]
    ) -> bool:
        if since is not None and ev.observed_at < since:
            return False
        if until is not None and ev.observed_at > until:
            return False
        return True

    def _filler(self, builder: EvidenceBuilder) -> Iterator[Evidence]:
        """
        Unlabelled background population.

        Exists for volume and crash-shaking only. Nothing asserts anything about
        it, because nobody knows what the right answer is for a random identity.
        """
        rng = random.Random(f"{self.seed}:filler")
        for i in range(self.filler_identities):
            ident = f"filler_user_{i:04d}"
            res = f"filler_res_{i % 7:04d}"
            yield builder.identity(
                ident, f"Filler {i}", "human", rng.choice(self.DEPARTMENTS)
            )
            yield builder.resource(
                res,
                f"Filler Resource {i % 7}",
                rng.choice(self.RESOURCE_TYPES),
                rng.choice(self.SENSITIVITIES),
            )
            lifecycle = rng.choice(("standing", "time_bound", "jit_eligible"))
            granted_at = builder.ago(days=rng.randrange(1, 500))
            # An expiring lifecycle without an expiry is a standing grant lying
            # about itself; the domain model rejects it, so the generator must
            # not emit it. Some expiries land in the past on purpose -- a grant
            # still present after expiry usually means revocation failed.
            expires_at = (
                granted_at + timedelta(days=rng.randrange(1, 120))
                if lifecycle == "time_bound"
                else None
            )
            yield builder.grant(
                f"g_filler_{i:04d}",
                ident,
                res,
                rng.choice(self.ACTIONS),
                lifecycle=lifecycle,
                granted_at=granted_at,
                expires_at=expires_at,
            )
            for j in range(rng.randrange(0, 5)):
                yield builder.event(
                    f"e_filler_{i:04d}_{j}",
                    ident,
                    res,
                    rng.choice(("read", "write", "login")),
                    builder.ago(days=rng.randrange(0, 30), minutes=rng.randrange(0, 1440)),
                    success=rng.random() > 0.1,
                )
