"""FRESH v3 -- written code-blind (2026-10-01): its author never opened the rule
or graph code, the tests, the README or the git history, and labelled only from
plain-language factor-type definitions. Not fully blind: the harness loaded
CLAUDE.md, which describes the rules in prose, into the author's context. More
independent than v1/v2 (written by the rule author); a human-written blind set
is still a parked TODO item.


Each scenario plants one real-world situation from a domain chosen to be
unlike the training corpus (hospitals, water and power utilities, universities,
libraries, airlines, retail, gaming, biotech, local government, legal,
clinical trials, hotels, payroll, K-12 districts, telehealth). Labels state
what is true and risky about the situation, per the factor-type definitions,
not what any detector is expected to do. Negative controls are traps: the same
shape as something risky, innocent for the reason given in the rationale.

The set is graph-weighted: most scenarios turn on multi-hop access -- roles
reached by impersonation, control planes that govern other resources, long
chains, JIT hops, roles that hold nothing, and routes that end short of a
crown jewel.

Builders here never import the synthetic module at top level (it imports this
one); the scenario tuple is built lazily in `fresh_v3_scenarios()`.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.connectors.synthetic import EvidenceBuilder
    from app.evidence.models import Evidence


# --------------------------------------------------------------------------
# Small helpers for repetitive activity. Event ids are derived from a tag and
# an index, never from a timestamp.
# --------------------------------------------------------------------------


def _daily(
    b: "EvidenceBuilder",
    tag: str,
    identity_id: str,
    resource_id: str,
    action: str,
    days: range,
    hours: float = 14,
) -> "list[Evidence]":
    """One event per day in `days` (days ago), at a fixed offset of hours."""
    return [
        b.event(f"v3_ev_{tag}_{d}", identity_id, resource_id, action, b.ago(days=d, hours=hours))
        for d in days
    ]


def _burst(
    b: "EvidenceBuilder",
    tag: str,
    identity_id: str,
    resource_id: str,
    action: str,
    count: int,
    start_days: float,
    start_hours: float,
    spacing_seconds: float,
    success: bool = True,
) -> "list[Evidence]":
    """`count` events packed together, spaced `spacing_seconds` apart."""
    return [
        b.event(
            f"v3_ev_{tag}_{i}",
            identity_id,
            resource_id,
            action,
            b.ago(days=start_days, hours=start_hours, seconds=-spacing_seconds * i),
            success,
        )
        for i in range(count)
    ]


# --------------------------------------------------------------------------
# Graph-centred situations
# --------------------------------------------------------------------------


def _v3_hospital_pharmacy_chain(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Hospital clinical informatics. Nadia, an informatics nurse, holds standing
    impersonation of the EHR support role so she can troubleshoot charting.
    Years ago someone let the EHR support role assume the pharmacy operations
    role (to fix order-set sync), and the pharmacy role is admin on the
    controlled-substance dispensing database. Nadia holds no grant on that
    database, yet a standing two-role chain hands her full control of it.
    She uses her own grant every working day, so nothing here is stale.
    """
    return [
        b.identity("v3_nadia_rn", "Nadia Okafor", "human", "Clinical Informatics"),
        b.identity("v3_role_ehr_support", "EHR support role", "role", "Clinical Informatics"),
        b.identity("v3_role_pharmacy_ops", "Pharmacy operations role", "role", "Pharmacy"),
        b.resource(
            "v3_res_ehr_support_role", "EHR support role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_ehr_support",
        ),
        b.resource(
            "v3_res_pharmacy_ops_role", "Pharmacy ops role (assumable)", "cloud_account", "high",
            principal_id="v3_role_pharmacy_ops",
        ),
        b.resource("v3_res_ehr_charting_db", "EHR charting replica", "database", "high"),
        b.resource(
            "v3_res_controlled_rx_db", "Controlled-substance dispensing DB", "database", "critical"
        ),
        b.resource("v3_res_nursing_wiki", "Nursing informatics wiki", "repository", "low"),
        b.grant(
            "v3_g_nadia_ehr_role", "v3_nadia_rn", "v3_res_ehr_support_role", "impersonate",
            granted_at=b.ago(days=700),
        ),
        b.grant(
            "v3_g_nadia_wiki", "v3_nadia_rn", "v3_res_nursing_wiki", "write",
            granted_at=b.ago(days=700),
        ),
        b.grant(
            "v3_g_ehrrole_chart", "v3_role_ehr_support", "v3_res_ehr_charting_db", "read",
            granted_at=b.ago(days=900),
        ),
        b.grant(
            "v3_g_ehrrole_pharm", "v3_role_ehr_support", "v3_res_pharmacy_ops_role", "impersonate",
            granted_at=b.ago(days=850),
        ),
        b.grant(
            "v3_g_pharmrole_rx", "v3_role_pharmacy_ops", "v3_res_controlled_rx_db", "admin",
            granted_at=b.ago(days=1200),
        ),
        *_daily(b, "nadia_assume", "v3_nadia_rn", "v3_res_ehr_support_role", "assume_role",
                range(1, 40), hours=15),
        *_daily(b, "nadia_chart", "v3_nadia_rn", "v3_res_ehr_charting_db", "read",
                range(1, 40), hours=14.5),
        *_daily(b, "nadia_wiki", "v3_nadia_rn", "v3_res_nursing_wiki", "write",
                range(2, 40, 3), hours=12),
    ]


def _v3_water_scada_jit_hop(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Municipal water utility. Omar, a field operations engineer, holds standing
    impersonation of the field-ops role, which he uses every day. The field-ops
    role may *request* the SCADA admin role (JIT, approval by the control-room
    supervisor), and only the SCADA admin role controls the treatment-plant
    SCADA. The chain looks like a route to the crown jewel, but one hop needs
    an approval, so it is not a standing route -- this is the remediated state.
    """
    return [
        b.identity("v3_omar_field_eng", "Omar Haddad", "human", "Water Field Operations"),
        b.identity("v3_role_field_ops", "Field ops role", "role", "Water Field Operations"),
        b.identity("v3_role_scada_admin", "SCADA admin role", "role", "Control Room"),
        b.resource(
            "v3_res_field_ops_role", "Field ops role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_field_ops",
        ),
        b.resource(
            "v3_res_scada_admin_role", "SCADA admin role (assumable)", "cloud_account", "high",
            principal_id="v3_role_scada_admin",
        ),
        b.resource("v3_res_hydrant_map", "Hydrant and valve map", "api", "medium"),
        b.resource("v3_res_treatment_scada", "Treatment plant SCADA", "server", "critical"),
        b.grant(
            "v3_g_omar_fieldrole", "v3_omar_field_eng", "v3_res_field_ops_role", "impersonate",
            granted_at=b.ago(days=500),
        ),
        b.grant(
            "v3_g_fieldrole_map", "v3_role_field_ops", "v3_res_hydrant_map", "write",
            granted_at=b.ago(days=800),
        ),
        b.grant(
            "v3_g_fieldrole_scada_jit", "v3_role_field_ops", "v3_res_scada_admin_role",
            "impersonate", lifecycle="jit_eligible", granted_at=b.ago(days=300),
        ),
        b.grant(
            "v3_g_scadarole_admin", "v3_role_scada_admin", "v3_res_treatment_scada", "admin",
            granted_at=b.ago(days=1000),
        ),
        *_daily(b, "omar_assume", "v3_omar_field_eng", "v3_res_field_ops_role", "assume_role",
                range(1, 35), hours=16),
        *_daily(b, "omar_map", "v3_omar_field_eng", "v3_res_hydrant_map", "write",
                range(1, 35), hours=15),
    ]


def _v3_campus_iam_plane(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    University. Li, on the IT service desk, holds standing permission
    management on the campus IAM console so he can add student workers to
    groups. The console is rated MEDIUM, but it governs the student records
    system (critical, FERPA-protected) and the research grants ledger, so Li
    can grant himself anything on them. He uses the console weekly, so it is
    neither unused nor new; the risk is the route and the power it confers.

    Also on campus: Amara, a chemistry PhD student, kept standing write on the
    lab instrument data store after moving to a computational project eight
    months ago. She is active every day on the learning platform but has not
    touched the instrument data since.
    """
    return [
        b.identity("v3_li_servicedesk", "Li Wei", "human", "IT Service Desk"),
        b.identity("v3_amara_phd", "Amara Nwosu", "human", "Chemistry"),
        b.resource(
            "v3_res_campus_iam", "Campus IAM console", "cloud_account", "medium",
            governs=("v3_res_student_records", "v3_res_grants_ledger"),
        ),
        b.resource("v3_res_student_records", "Student records system", "database", "critical"),
        b.resource("v3_res_grants_ledger", "Research grants ledger", "database", "high"),
        b.resource("v3_res_lab_instrument_data", "Lab instrument data store", "database", "high"),
        b.resource("v3_res_campus_lms", "Learning management system", "api", "low"),
        b.grant(
            "v3_g_li_iam", "v3_li_servicedesk", "v3_res_campus_iam", "manage_permission",
            granted_at=b.ago(days=420),
        ),
        b.grant(
            "v3_g_amara_instr", "v3_amara_phd", "v3_res_lab_instrument_data", "write",
            granted_at=b.ago(days=640),
        ),
        b.grant(
            "v3_g_amara_lms", "v3_amara_phd", "v3_res_campus_lms", "read",
            granted_at=b.ago(days=640),
        ),
        *_daily(b, "li_grant", "v3_li_servicedesk", "v3_res_campus_iam", "grant_permission",
                range(2, 60, 7), hours=13),
        *_daily(b, "li_login", "v3_li_servicedesk", "v3_res_campus_iam", "login",
                range(1, 60, 2), hours=15),
        *_daily(b, "amara_instr", "v3_amara_phd", "v3_res_lab_instrument_data", "write",
                range(250, 620, 6), hours=11),
        *_daily(b, "amara_lms", "v3_amara_phd", "v3_res_campus_lms", "read",
                range(1, 60), hours=10),
    ]


def _v3_library_iam_plane(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Public library system. Greta, the library systems administrator, holds
    standing permission management on the library access console, exactly the
    shape of a campus IAM console. But this console governs only the book
    catalogue, the meeting-room booking system and the e-book proxy -- nothing
    above MEDIUM. Her power is broad in kind but low in stakes: no crown jewel
    is reachable, and no HIGH or CRITICAL resource is under her control.
    """
    return [
        b.identity("v3_greta_libsys", "Greta Lindqvist", "human", "Library Services"),
        b.resource(
            "v3_res_lib_access_console", "Library access console", "cloud_account", "medium",
            governs=("v3_res_lib_catalog", "v3_res_lib_room_booking", "v3_res_lib_ebook_proxy"),
        ),
        b.resource("v3_res_lib_catalog", "Book catalogue", "database", "low"),
        b.resource("v3_res_lib_room_booking", "Meeting-room booking", "api", "medium"),
        b.resource("v3_res_lib_ebook_proxy", "E-book proxy", "server", "low"),
        b.grant(
            "v3_g_greta_console", "v3_greta_libsys", "v3_res_lib_access_console",
            "manage_permission", granted_at=b.ago(days=900),
        ),
        *_daily(b, "greta_grant", "v3_greta_libsys", "v3_res_lib_access_console",
                "grant_permission", range(3, 60, 7), hours=13),
        *_daily(b, "greta_login", "v3_greta_libsys", "v3_res_lib_access_console", "login",
                range(1, 60, 2), hours=15),
    ]


def _v3_airline_ops_role_breadth(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Airline operations. The crew-pairing optimiser service assumes a shared
    "ops platform" role every night. Over the years the role accreted access to
    almost every operational system: flight operations and passenger manifests
    (both crown jewels), the crew roster, maintenance logs, gate assignment,
    fuel planning and the weather feed. A stolen token for this one service
    reaches those seven plus its own workspace, two of them critical --
    breadth through a role.

    Also here: the tagged break-glass account for the ops failover console.
    It holds standing admin and has never been used since it was set up -- its
    designed state. It is unused, not stale.
    """
    svc = "v3_svc_crew_pairing"
    role_targets = [
        ("v3_g_opsrole_flightops", "v3_res_flight_ops_db", "read"),
        ("v3_g_opsrole_manifest", "v3_res_pax_manifest", "read"),
        ("v3_g_opsrole_roster", "v3_res_crew_roster", "write"),
        ("v3_g_opsrole_mx", "v3_res_mx_logs", "read"),
        ("v3_g_opsrole_gate", "v3_res_gate_api", "write"),
        ("v3_g_opsrole_fuel", "v3_res_fuel_planning", "read"),
        ("v3_g_opsrole_wx", "v3_res_wx_feed", "read"),
    ]
    records = [
        b.identity(svc, "Crew pairing optimiser", "service", "Flight Operations"),
        b.identity("v3_role_ops_platform", "Ops platform role", "role", "Flight Operations"),
        b.identity(
            "v3_bg_ops_failover", "Ops failover break-glass", "human", "Flight Operations",
            is_break_glass=True,
        ),
        b.resource(
            "v3_res_ops_platform_role", "Ops platform role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_ops_platform",
        ),
        b.resource("v3_res_flight_ops_db", "Flight operations DB", "database", "critical"),
        b.resource("v3_res_pax_manifest", "Passenger manifests", "database", "critical"),
        b.resource("v3_res_crew_roster", "Crew roster", "database", "high"),
        b.resource("v3_res_mx_logs", "Aircraft maintenance logs", "database", "high"),
        b.resource("v3_res_gate_api", "Gate assignment API", "api", "medium"),
        b.resource("v3_res_fuel_planning", "Fuel planning API", "api", "medium"),
        b.resource("v3_res_wx_feed", "Weather feed", "api", "low"),
        b.resource("v3_res_pairing_engine", "Pairing engine workspace", "server", "medium"),
        b.resource("v3_res_ops_failover_console", "Ops failover console", "cloud_account", "critical"),
        b.grant(
            "v3_g_crewpair_role", svc, "v3_res_ops_platform_role", "impersonate",
            granted_at=b.ago(days=1100),
        ),
        b.grant(
            "v3_g_crewpair_engine", svc, "v3_res_pairing_engine", "write",
            granted_at=b.ago(days=1100),
        ),
        b.grant(
            "v3_g_bg_failover", "v3_bg_ops_failover", "v3_res_ops_failover_console", "admin",
            granted_at=b.ago(days=480),
        ),
        *_daily(b, "crewpair_assume", svc, "v3_res_ops_platform_role", "assume_role",
                range(1, 35), hours=21),
        *_daily(b, "crewpair_engine", svc, "v3_res_pairing_engine", "write",
                range(1, 35), hours=20),
    ]
    for grant_id, res, action in role_targets:
        records.append(
            b.grant(grant_id, "v3_role_ops_platform", res, action, granted_at=b.ago(days=1000))
        )
        ev_action = "write" if action == "write" else "read"
        records.extend(
            _daily(b, f"crewpair_{res}", svc, res, ev_action, range(1, 35), hours=20.5)
        )
    return records


def _v3_retail_store_systems(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Grocery retailer. The store-KPI reporting service assumes a reporting role
    that reads eight store systems -- footfall counters, weather, promo
    calendar, store hours, staffing rota, planogram, energy meters, and its own
    KPI warehouse. Wide, but nothing in it is above MEDIUM: compromise would
    leak store trivia, not a crown jewel. Many systems with no crown jewel is
    not an excessive blast radius.

    Same retailer: the POS settlement service account runs a nightly batch,
    but store managers share its credential to rerun failed settlements by
    hand, so over the last two weeks it logs in interactively several times a
    day during business hours. A service account used as a person is a context
    mismatch.
    """
    kpi = "v3_svc_store_kpi"
    pos = "v3_svc_pos_settlement"
    reporting_targets = [
        ("v3_g_rptrole_footfall", "v3_res_footfall_counts", "low"),
        ("v3_g_rptrole_wx", "v3_res_store_weather", "low"),
        ("v3_g_rptrole_promo", "v3_res_promo_calendar", "low"),
        ("v3_g_rptrole_hours", "v3_res_store_hours", "low"),
        ("v3_g_rptrole_rota", "v3_res_staffing_rota", "medium"),
        ("v3_g_rptrole_plano", "v3_res_planogram_db", "medium"),
        ("v3_g_rptrole_energy", "v3_res_energy_meters", "low"),
    ]
    records = [
        b.identity(kpi, "Store KPI reporting", "service", "Retail Analytics"),
        b.identity(pos, "POS settlement batch", "service", "Store Systems"),
        b.identity("v3_role_store_reporting", "Store reporting role", "role", "Retail Analytics"),
        b.resource(
            "v3_res_store_reporting_role", "Store reporting role (assumable)", "cloud_account",
            "low", principal_id="v3_role_store_reporting",
        ),
        b.resource("v3_res_kpi_warehouse", "Store KPI warehouse", "database", "medium"),
        b.resource("v3_res_pos_settlement_srv", "POS settlement server", "server", "high"),
        b.grant(
            "v3_g_kpi_role", kpi, "v3_res_store_reporting_role", "impersonate",
            granted_at=b.ago(days=600),
        ),
        b.grant(
            "v3_g_kpi_wh", kpi, "v3_res_kpi_warehouse", "write", granted_at=b.ago(days=600),
        ),
        b.grant(
            "v3_g_pos_auth", pos, "v3_res_pos_settlement_srv", "authenticate",
            granted_at=b.ago(days=800),
        ),
        b.grant(
            "v3_g_pos_write", pos, "v3_res_pos_settlement_srv", "write",
            granted_at=b.ago(days=800),
        ),
        *_daily(b, "kpi_assume", kpi, "v3_res_store_reporting_role", "assume_role",
                range(1, 35), hours=19),
        *_daily(b, "kpi_wh", kpi, "v3_res_kpi_warehouse", "write", range(1, 35), hours=18),
        # The nightly batch at ~02:00.
        *_daily(b, "pos_batch", pos, "v3_res_pos_settlement_srv", "write",
                range(1, 45), hours=22),
    ]
    for grant_id, res, sens in reporting_targets:
        records.append(b.resource(res, res.replace("v3_res_", "").replace("_", " "), "api", sens))
        records.append(
            b.grant(grant_id, "v3_role_store_reporting", res, "read", granted_at=b.ago(days=600))
        )
        records.extend(_daily(b, f"kpi_{res}", kpi, res, "read", range(1, 35), hours=18.5))
    # Interactive logins by store managers: ~09:10, ~13:40, ~16:25 local, last 14 days.
    for d in range(1, 15):
        for slot, hours in enumerate((14.8, 10.3, 7.6)):
            records.append(
                b.event(
                    f"v3_ev_pos_human_login_{d}_{slot}", pos, "v3_res_pos_settlement_srv",
                    "login", b.ago(days=d, hours=hours, minutes=(d * 7 + slot * 13) % 40),
                )
            )
    return records


def _v3_game_wallet_dba(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Online game studio. Soren, the economy DBA, holds five standing grants on
    the player wallet database (real-money balances, a crown jewel): read,
    write, destroy, admin and permission management. He uses them -- weekly
    purges of expired holds, monthly access grants for analysts -- but every
    one is standing; nothing about routine DBA work needs always-on destroy
    and admin over real-money balances. That is excessive privilege.
    It is *depth* on one system, though: apart from a low-value telemetry
    store he reaches nothing else. Many grants on one resource is not breadth.
    """
    s = "v3_soren_dba"
    w = "v3_res_player_wallet_db"
    return [
        b.identity(s, "Soren Holm", "human", "Game Economy"),
        b.resource(w, "Player wallet DB", "database", "critical"),
        b.resource("v3_res_game_telemetry", "Gameplay telemetry", "database", "low"),
        b.grant("v3_g_soren_read", s, w, "read", granted_at=b.ago(days=730)),
        b.grant("v3_g_soren_write", s, w, "write", granted_at=b.ago(days=730)),
        b.grant("v3_g_soren_destroy", s, w, "destroy", granted_at=b.ago(days=730)),
        b.grant("v3_g_soren_admin", s, w, "admin", granted_at=b.ago(days=730)),
        b.grant("v3_g_soren_mperm", s, w, "manage_permission", granted_at=b.ago(days=730)),
        b.grant(
            "v3_g_soren_telemetry", s, "v3_res_game_telemetry", "read",
            granted_at=b.ago(days=730),
        ),
        *_daily(b, "soren_login", s, w, "login", range(1, 60, 2), hours=15),
        *_daily(b, "soren_read", s, w, "read", range(1, 60, 2), hours=14),
        *_daily(b, "soren_write", s, w, "write", range(2, 60, 4), hours=13),
        *_daily(b, "soren_delete", s, w, "delete", range(3, 60, 7), hours=12),
        *_daily(b, "soren_grant", s, w, "grant_permission", range(5, 60, 28), hours=11),
        *_daily(b, "soren_tel", s, "v3_res_game_telemetry", "read", range(1, 60, 3), hours=10),
    ]


def _v3_biotech_empty_role(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Genomics biotech. Ingrid, a scientist, holds standing impersonation of the
    "sequencer admin" role and a lab script still assumes it weekly. The name
    sounds dangerous and the genome vault sits in the same estate, but the
    role was emptied during last year's sequencer migration: it holds no
    grants at all. Stepping into it gains nothing, so there is no route.
    """
    return [
        b.identity("v3_ingrid_sci", "Ingrid Bauer", "human", "Genomics"),
        b.identity("v3_role_sequencer_admin", "Sequencer admin role", "role", "Genomics"),
        b.resource(
            "v3_res_sequencer_admin_role", "Sequencer admin role (assumable)", "cloud_account",
            "medium", principal_id="v3_role_sequencer_admin",
        ),
        b.resource("v3_res_genome_vault", "Patient genome vault", "database", "critical"),
        b.resource("v3_res_genomics_lims", "Genomics LIMS", "database", "medium"),
        b.grant(
            "v3_g_ingrid_seqrole", "v3_ingrid_sci", "v3_res_sequencer_admin_role", "impersonate",
            granted_at=b.ago(days=540),
        ),
        b.grant(
            "v3_g_ingrid_lims", "v3_ingrid_sci", "v3_res_genomics_lims", "write",
            granted_at=b.ago(days=540),
        ),
        *_daily(b, "ingrid_assume", "v3_ingrid_sci", "v3_res_sequencer_admin_role",
                "assume_role", range(1, 60, 7), hours=17),
        *_daily(b, "ingrid_lims", "v3_ingrid_sci", "v3_res_genomics_lims", "write",
                range(1, 40), hours=14),
    ]


def _v3_permits_route_high(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    City government. Hal, a permits clerk, assumes the permits-ops role daily;
    that role can step into the permits DBA role, which is admin on the
    building-permits database. A real two-role chain -- but it ends at a HIGH
    system, not a crown jewel. Whatever else one thinks of it, a route that
    does not end at something CRITICAL is not privilege escalation here.
    """
    return [
        b.identity("v3_hal_permits", "Hal Brennan", "human", "Planning & Permits"),
        b.identity("v3_role_permits_ops", "Permits ops role", "role", "Planning & Permits"),
        b.identity("v3_role_permits_dba", "Permits DBA role", "role", "City IT"),
        b.resource(
            "v3_res_permits_ops_role", "Permits ops role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_permits_ops",
        ),
        b.resource(
            "v3_res_permits_dba_role", "Permits DBA role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_permits_dba",
        ),
        b.resource("v3_res_permits_db", "Building permits DB", "database", "high"),
        b.resource("v3_res_permits_portal", "Public permits portal", "api", "low"),
        b.grant(
            "v3_g_hal_opsrole", "v3_hal_permits", "v3_res_permits_ops_role", "impersonate",
            granted_at=b.ago(days=400),
        ),
        b.grant(
            "v3_g_opsrole_portal", "v3_role_permits_ops", "v3_res_permits_portal", "write",
            granted_at=b.ago(days=900),
        ),
        b.grant(
            "v3_g_opsrole_dbarole", "v3_role_permits_ops", "v3_res_permits_dba_role",
            "impersonate", granted_at=b.ago(days=900),
        ),
        b.grant(
            "v3_g_dbarole_permits", "v3_role_permits_dba", "v3_res_permits_db", "admin",
            granted_at=b.ago(days=900),
        ),
        *_daily(b, "hal_assume", "v3_hal_permits", "v3_res_permits_ops_role", "assume_role",
                range(1, 40), hours=15),
        *_daily(b, "hal_portal", "v3_hal_permits", "v3_res_permits_portal", "write",
                range(1, 40), hours=14),
    ]


def _v3_legal_long_chain(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Law firm. Kai works for an external e-discovery vendor and holds standing
    impersonation of the document-review role, which he uses daily. Through
    four role-to-role trust links set up by different teams over the years --
    review -> matter ops -> records management -> legal-hold admin -- the
    legal-hold admin role is admin on the privileged-documents vault. Five
    hops is long and each link looked harmless alone, but the route is real,
    standing, and ends in control of a crown jewel he holds no grant on.
    """
    k = "v3_kai_ediscovery"
    return [
        b.identity(k, "Kai Moreno", "human", "External Counsel", is_external=True),
        b.identity("v3_role_doc_review", "Document review role", "role", "Litigation Support"),
        b.identity("v3_role_matter_ops", "Matter ops role", "role", "Litigation Support"),
        b.identity("v3_role_records_mgmt", "Records management role", "role", "Records"),
        b.identity("v3_role_legal_hold_admin", "Legal hold admin role", "role", "Records"),
        b.resource(
            "v3_res_doc_review_role", "Doc review role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_doc_review",
        ),
        b.resource(
            "v3_res_matter_ops_role", "Matter ops role (assumable)", "cloud_account", "medium",
            principal_id="v3_role_matter_ops",
        ),
        b.resource(
            "v3_res_records_mgmt_role", "Records mgmt role (assumable)", "cloud_account",
            "medium", principal_id="v3_role_records_mgmt",
        ),
        b.resource(
            "v3_res_legal_hold_role", "Legal hold admin role (assumable)", "cloud_account",
            "high", principal_id="v3_role_legal_hold_admin",
        ),
        b.resource("v3_res_review_corpus", "E-discovery review corpus", "database", "high"),
        b.resource(
            "v3_res_privileged_docs_vault", "Privileged documents vault", "database", "critical"
        ),
        b.grant("v3_g_kai_review", k, "v3_res_doc_review_role", "impersonate",
                granted_at=b.ago(days=380)),
        b.grant("v3_g_review_corpus", "v3_role_doc_review", "v3_res_review_corpus", "read",
                granted_at=b.ago(days=1400)),
        b.grant("v3_g_review_matter", "v3_role_doc_review", "v3_res_matter_ops_role",
                "impersonate", granted_at=b.ago(days=1300)),
        b.grant("v3_g_matter_records", "v3_role_matter_ops", "v3_res_records_mgmt_role",
                "impersonate", granted_at=b.ago(days=1100)),
        b.grant("v3_g_records_hold", "v3_role_records_mgmt", "v3_res_legal_hold_role",
                "impersonate", granted_at=b.ago(days=1000)),
        b.grant("v3_g_hold_vault", "v3_role_legal_hold_admin", "v3_res_privileged_docs_vault",
                "admin", granted_at=b.ago(days=1500)),
        *_daily(b, "kai_assume", k, "v3_res_doc_review_role", "assume_role",
                range(1, 40), hours=16),
        *_daily(b, "kai_corpus", k, "v3_res_review_corpus", "read", range(1, 40), hours=15),
    ]


def _v3_ot_broker_governs_role(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Electric utility, operational technology. Bea manages vendor access for
    substation engineering and holds standing permission management on the OT
    access broker. The broker is rated MEDIUM, but it governs the substation
    maintenance role, and that role is admin on the RTU fleet that switches
    the grid -- a crown jewel. Bea can grant herself the maintenance role and
    step through it. She uses the broker weekly, so the grant is live and
    exercised; the risk is what it leads to.
    """
    bea = "v3_bea_ot_access"
    return [
        b.identity(bea, "Bea Kowalczyk", "human", "Substation Engineering"),
        b.identity("v3_role_substation_maint", "Substation maintenance role", "role",
                   "Substation Engineering"),
        b.resource(
            "v3_res_ot_access_broker", "OT access broker", "cloud_account", "medium",
            governs=("v3_res_substation_maint_role",),
        ),
        b.resource(
            "v3_res_substation_maint_role", "Substation maint role (assumable)", "cloud_account",
            "high", principal_id="v3_role_substation_maint",
        ),
        b.resource("v3_res_rtu_fleet", "Substation RTU fleet", "server", "critical"),
        b.grant("v3_g_bea_broker", bea, "v3_res_ot_access_broker", "manage_permission",
                granted_at=b.ago(days=610)),
        b.grant("v3_g_maint_rtu", "v3_role_substation_maint", "v3_res_rtu_fleet", "admin",
                granted_at=b.ago(days=1300)),
        *_daily(b, "bea_grant", bea, "v3_res_ot_access_broker", "grant_permission",
                range(2, 60, 7), hours=13),
        *_daily(b, "bea_revoke", bea, "v3_res_ot_access_broker", "revoke_permission",
                range(4, 60, 14), hours=12),
        *_daily(b, "bea_login", bea, "v3_res_ot_access_broker", "login",
                range(1, 60, 2), hours=15),
    ]


def _v3_trial_expired_hop(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Pharmaceutical clinical trial. Lena, a clinical operations lead, was given
    a time-bound grant to assume the unblinded-data role for an interim
    safety analysis. The window closed two months ago, but the grant is still
    attached -- revocation never ran. She used it inside the window and has not
    since; she remains active on the trial management system daily. An
    expired time-bound grant still attached is stale access.
    """
    lena = "v3_lena_clinops"
    return [
        b.identity(lena, "Lena Fischer", "human", "Clinical Operations"),
        b.identity("v3_role_trial_unblinded", "Trial unblinded-data role", "role", "Biostatistics"),
        b.resource(
            "v3_res_trial_unblinded_role", "Unblinded role (assumable)", "cloud_account", "high",
            principal_id="v3_role_trial_unblinded",
        ),
        b.resource("v3_res_trial_edc", "Trial EDC (unblinded)", "database", "critical"),
        b.resource("v3_res_trial_ctms", "Clinical trial management", "api", "medium"),
        b.grant(
            "v3_g_lena_unblind", lena, "v3_res_trial_unblinded_role", "impersonate",
            lifecycle="time_bound", granted_at=b.ago(days=150), expires_at=b.ago(days=60),
        ),
        b.grant("v3_g_lena_ctms", lena, "v3_res_trial_ctms", "read", granted_at=b.ago(days=800)),
        b.grant("v3_g_unblind_edc", "v3_role_trial_unblinded", "v3_res_trial_edc", "read",
                granted_at=b.ago(days=1000)),
        *_daily(b, "lena_assume", lena, "v3_res_trial_unblinded_role", "assume_role",
                range(65, 148, 4), hours=14),
        *_daily(b, "lena_ctms", lena, "v3_res_trial_ctms", "read", range(1, 60), hours=13),
    ]


# --------------------------------------------------------------------------
# Other factor types
# --------------------------------------------------------------------------


def _v3_hotel_rate_outlier(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Hotel chain. The rate-strategy database (pricing floors, corporate
    contract rates -- HIGH) is held by six revenue-management analysts and one
    marketing coordinator, Paula, who was added for a campaign two years ago
    and still reads it weekly. She is the only holder from outside revenue
    management: access unlike everyone else's.
    """
    db = "v3_res_rate_strategy_db"
    analysts = [
        ("v3_rm_analyst_ade", "Ade Bello"),
        ("v3_rm_analyst_bri", "Bri Tanaka"),
        ("v3_rm_analyst_cas", "Cas Novak"),
        ("v3_rm_analyst_dee", "Dee Arslan"),
        ("v3_rm_analyst_eli", "Eli Romero"),
        ("v3_rm_analyst_fay", "Fay Odum"),
    ]
    records = [
        b.resource(db, "Rate strategy DB", "database", "high"),
        b.identity("v3_paula_mkt", "Paula Greco", "human", "Marketing"),
        b.grant("v3_g_paula_rate", "v3_paula_mkt", db, "read", granted_at=b.ago(days=760)),
        *_daily(b, "paula_rate", "v3_paula_mkt", db, "read", range(2, 60, 7), hours=13),
    ]
    for ident, name in analysts:
        records.append(b.identity(ident, name, "human", "Revenue Management"))
        records.append(b.grant(f"v3_g_{ident}_rate", ident, db, "read", granted_at=b.ago(days=700)))
        records.extend(_daily(b, f"{ident}_rate", ident, db, "read", range(1, 40), hours=14))
    return records


def _v3_radiology_failed_burst(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Hospital radiology. Owen, a radiology technologist, normally opens a
    handful of studies a day in the imaging archive. Three hours ago his
    account took 24 failed logins in about twelve minutes, then a success,
    then pulled 180 studies in forty minutes -- a credential-stuffing burst
    followed by bulk exfiltration. Unusual for this identity on both counts.
    """
    o = "v3_owen_radtech"
    pacs = "v3_res_pacs_archive"
    return [
        b.identity(o, "Owen Price", "human", "Radiology"),
        b.resource(pacs, "Imaging archive (PACS)", "database", "high"),
        b.grant("v3_g_owen_pacs", o, pacs, "read", granted_at=b.ago(days=900)),
        *[
            ev
            for d in range(1, 45)
            for ev in (
                b.event(f"v3_ev_owen_login_{d}", o, pacs, "login", b.ago(days=d, hours=16)),
                b.event(f"v3_ev_owen_r1_{d}", o, pacs, "read", b.ago(days=d, hours=15)),
                b.event(f"v3_ev_owen_r2_{d}", o, pacs, "read", b.ago(days=d, hours=13)),
                b.event(f"v3_ev_owen_r3_{d}", o, pacs, "read", b.ago(days=d, hours=11)),
            )
        ],
        *_burst(b, "owen_fail", o, pacs, "login", 24, 0, 3.25, 30, success=False),
        b.event("v3_ev_owen_breach_login", o, pacs, "login", b.ago(hours=3, minutes=2)),
        *_burst(b, "owen_bulk", o, pacs, "read", 180, 0, 3, 13),
    ]


def _v3_payroll_cycles(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Logistics company payroll. The payroll export service reads ~60 employee
    pay records in one hour at every pay cycle (every 30 days), and has done
    so for six cycles; yesterday's run looks exactly like the others. Heavy,
    but heavy in its own normal way -- not anomalous.

    Dmitri, a payroll analyst on the same database, normally looks up two or
    three records a day. Six hours ago he read 150 in under an hour, far above
    anything in his own history.
    """
    svc = "v3_svc_payroll_export"
    dm = "v3_dmitri_payroll"
    db = "v3_res_payroll_records"
    records = [
        b.identity(svc, "Payroll export", "service", "Payroll"),
        b.identity(dm, "Dmitri Volkov", "human", "Payroll"),
        b.resource(db, "Employee pay records", "database", "high"),
        b.grant("v3_g_payexp_read", svc, db, "read", granted_at=b.ago(days=1000)),
        b.grant("v3_g_dmitri_read", dm, db, "read", granted_at=b.ago(days=1000)),
    ]
    for cycle in range(6):
        records.extend(
            _burst(b, f"payexp_c{cycle}", svc, db, "read", 60, 1 + 30 * cycle, 3, 55)
        )
    for d in range(1, 60):
        for k, hours in enumerate((15, 13, 10)[: 2 + d % 2]):
            records.append(b.event(f"v3_ev_dmitri_{d}_{k}", dm, db, "read", b.ago(days=d, hours=hours)))
    records.extend(_burst(b, "dmitri_bulk", dm, db, "read", 150, 0, 6, 20))
    return records


def _v3_k12_annual_rollover(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    K-12 school district. The enrollment rollover service promotes every
    student to the next grade once a year in late summer, and has done so for
    four years. Its last run was about eleven months ago and it has been
    silent since -- which is exactly its rhythm. Quiet is not dormant for a
    yearly job, and its grants are used every cycle.
    """
    svc = "v3_svc_enroll_rollover"
    sis = "v3_res_district_sis"
    records = [
        b.identity(svc, "Enrollment rollover", "service", "District IT"),
        b.resource(sis, "District student information system", "database", "high"),
        b.grant("v3_g_rollover_read", svc, sis, "read", granted_at=b.ago(days=1500)),
        b.grant("v3_g_rollover_write", svc, sis, "write", granted_at=b.ago(days=1500)),
    ]
    for year, day in enumerate((330, 695, 1060, 1425)):
        records.extend(_burst(b, f"rollover_r{year}", svc, sis, "read", 20, day, 4, 300))
        records.extend(_burst(b, f"rollover_w{year}", svc, sis, "write", 20, day, 2, 300))
    return records


def _v3_telehealth_public(b: "EvidenceBuilder", rng: random.Random) -> "list[Evidence]":
    """
    Telehealth provider. The patient portal API is internet-facing and holds
    patient visit records -- a public crown jewel. The portal deployer service
    holds standing deploy and admin on it; anyone who steals that token from
    the CI system controls an internet-facing system full of health data.

    Same company: an external web agency contractor holds standing admin on
    the public marketing site. External principal, admin, public -- but the
    site is a brochure with nothing of value on it (LOW). Not exposure of
    anything that matters.
    """
    dep = "v3_svc_portal_deployer"
    mo = "v3_mo_web_agency"
    api = "v3_res_patient_portal_api"
    site = "v3_res_marketing_site"
    return [
        b.identity(dep, "Portal deployer", "service", "Digital Health"),
        b.identity(mo, "Mo Sato", "human", "Web Agency", is_external=True),
        b.resource(api, "Patient portal API", "api", "critical", exposure="public"),
        b.resource(site, "Marketing website", "server", "low", exposure="public"),
        b.grant("v3_g_dep_deploy", dep, api, "deploy", granted_at=b.ago(days=500)),
        b.grant("v3_g_dep_admin", dep, api, "admin", granted_at=b.ago(days=500)),
        b.grant("v3_g_mo_site", mo, site, "admin", granted_at=b.ago(days=300)),
        *_daily(b, "dep_login", dep, api, "login", range(1, 40, 2), hours=20),
        *_daily(b, "dep_write", dep, api, "write", range(1, 40, 2), hours=19.5),
        *_daily(b, "mo_login", mo, site, "login", range(2, 60, 5), hours=14),
        *_daily(b, "mo_write", mo, site, "write", range(2, 60, 5), hours=13.5),
    ]


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


def fresh_v3_scenarios() -> tuple:
    from app.connectors.synthetic import FRESH, ExpectedFinding, Scenario

    return (
        Scenario(
            name="v3_hospital_pharmacy_chain",
            description="Informatics nurse -> EHR support role -> pharmacy ops role -> admin on controlled-substance DB.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_nadia_rn",
                    "A standing two-role chain gives her admin on a critical dispensing DB she holds no grant on.",
                ),
                ExpectedFinding(
                    "EXCESSIVE_BLAST_RADIUS", "v3_nadia_rn",
                    "Triage after the read (2026-10-01): one chain to one crown jewel is depth, not breadth; the "
                    "role resources on it are stepping-stones, already counted through "
                    "the roles' grants.",
                    should_fire=False,
                ),
            ),
            build=_v3_hospital_pharmacy_chain,
            split=FRESH,
        ),
        Scenario(
            name="v3_water_scada_jit_hop",
            description="Field engineer's role can only request the SCADA admin role JIT.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_omar_field_eng",
                    "The only hop towards SCADA is JIT-eligible and needs an approval; there is no standing route.",
                    should_fire=False,
                ),
            ),
            build=_v3_water_scada_jit_hop,
            split=FRESH,
        ),
        Scenario(
            name="v3_campus_iam_plane",
            description="Service-desk permission management on an IAM console governing student records; a PhD student's abandoned lab write grant.",
            expected=(
                # Label review before the read (2026-10-01): the author's brief
                # wrongly listed "managing a control plane that governs a
                # resource" under PRIVILEGE_ESCALATION. Corpus convention
                # (gustav): a standing path ending in permission management is
                # one finding, EXCESSIVE_PRIVILEGE. That label stays.
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_li_servicedesk",
                    "Standing permission management on a control plane that governs a critical system, for a help-desk task.",
                ),
                ExpectedFinding(
                    "STALE_ACCESS", "v3_amara_phd",
                    "Standing write on the lab instrument store unused for ~250 days while she is active elsewhere daily.",
                ),
            ),
            build=_v3_campus_iam_plane,
            split=FRESH,
        ),
        Scenario(
            name="v3_library_iam_plane",
            description="Library sysadmin manages permissions on a console that governs only low/medium library systems.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_greta_libsys",
                    "The control plane governs nothing critical, so there is no route to a crown jewel.",
                    should_fire=False,
                ),
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_greta_libsys",
                    "Permission management counts by what the plane governs: only LOW/MEDIUM library systems.",
                    should_fire=False,
                ),
            ),
            build=_v3_library_iam_plane,
            split=FRESH,
        ),
        Scenario(
            name="v3_airline_ops_role_breadth",
            description="Crew-pairing service reaches seven ops systems (two critical) through one shared role; tagged break-glass unused.",
            expected=(
                ExpectedFinding(
                    "EXCESSIVE_BLAST_RADIUS", "v3_svc_crew_pairing",
                    "Through the ops platform role it reaches eight systems, two of them crown jewels, all standing.",
                ),
                ExpectedFinding(
                    "STALE_ACCESS", "v3_bg_ops_failover",
                    "A tagged break-glass account being unused is its designed state.",
                    should_fire=False,
                ),
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_bg_ops_failover",
                    "Triage after the read (2026-10-01): the tag excuses staleness, never privilege: standing "
                    "admin on a crown jewel is still reported.",
                ),
            ),
            build=_v3_airline_ops_role_breadth,
            split=FRESH,
        ),
        Scenario(
            name="v3_retail_store_systems",
            description="Reporting service reads many low-value store systems; POS settlement service used interactively by managers.",
            expected=(
                ExpectedFinding(
                    "EXCESSIVE_BLAST_RADIUS", "v3_svc_store_kpi",
                    "Wide reach, but every system is LOW or MEDIUM; no crown jewel is reachable.",
                    should_fire=False,
                ),
                ExpectedFinding(
                    "CONTEXT_MISMATCH", "v3_svc_pos_settlement",
                    "A batch service account logging in interactively several times a day during business hours.",
                ),
            ),
            build=_v3_retail_store_systems,
            split=FRESH,
        ),
        Scenario(
            name="v3_game_wallet_dba",
            description="Economy DBA holds five standing grants, incl. destroy and admin, on the real-money wallet DB.",
            expected=(
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_soren_dba",
                    "Standing destroy, admin and permission management on a critical real-money database.",
                ),
                ExpectedFinding(
                    "EXCESSIVE_BLAST_RADIUS", "v3_soren_dba",
                    "Five grants on one resource plus a low telemetry store is depth, not breadth.",
                    should_fire=False,
                ),
            ),
            build=_v3_game_wallet_dba,
            split=FRESH,
        ),
        Scenario(
            name="v3_biotech_empty_role",
            description="Scientist assumes a 'sequencer admin' role that was emptied and holds nothing.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_ingrid_sci",
                    "The role she can step into holds no grants, so it leads nowhere.",
                    should_fire=False,
                ),
            ),
            build=_v3_biotech_empty_role,
            split=FRESH,
        ),
        Scenario(
            name="v3_permits_route_high",
            description="Permits clerk's two-role chain ends at admin on a HIGH (not critical) permits DB.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_hal_permits",
                    "The chain ends at a HIGH system, not a crown jewel.",
                    should_fire=False,
                ),
            ),
            build=_v3_permits_route_high,
            split=FRESH,
        ),
        Scenario(
            name="v3_legal_long_chain",
            description="External e-discovery vendor reaches admin on the privileged-docs vault via a five-hop role chain.",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_kai_ediscovery",
                    "A standing four-role chain ends in admin on a critical vault he holds no grant on; long, but real.",
                ),
                ExpectedFinding(
                    "EXCESSIVE_BLAST_RADIUS", "v3_kai_ediscovery",
                    "Triage after the read (2026-10-01): a single five-hop chain to one vault is depth, not "
                    "breadth; four of the six reachable resources are stepping-stone roles.",
                    should_fire=False,
                ),
            ),
            build=_v3_legal_long_chain,
            split=FRESH,
        ),
        Scenario(
            name="v3_ot_broker_governs_role",
            description="OT access manager manages a broker that governs the substation maintenance role (admin on RTUs).",
            expected=(
                ExpectedFinding(
                    "PRIVILEGE_ESCALATION", "v3_bea_ot_access",
                    "Managing the broker lets her grant herself the maintenance role, which controls the critical RTU fleet.",
                ),
                # Removed in a pre-read review that matched bea to xenia; wrong,
                # because bea's broker governs a HIGH role resource and xenia's
                # is MEDIUM. Restored in triage: the author's label was right.
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_bea_ot_access",
                    "Triage after the read (2026-10-01): standing permission management over a control plane "
                    "that governs a HIGH role resource. The author's original label.",
                ),
            ),
            build=_v3_ot_broker_governs_role,
            split=FRESH,
        ),
        Scenario(
            name="v3_trial_expired_hop",
            description="Time-bound grant to the unblinded-data role expired 60 days ago but is still attached.",
            expected=(
                ExpectedFinding(
                    "STALE_ACCESS", "v3_lena_clinops",
                    "A time-bound grant past its expiry is still attached and unused since the window closed.",
                ),
            ),
            build=_v3_trial_expired_hop,
            split=FRESH,
        ),
        Scenario(
            name="v3_hotel_rate_outlier",
            description="Only Marketing holder among six Revenue Management holders of the rate strategy DB.",
            expected=(
                ExpectedFinding(
                    "CONTEXT_MISMATCH", "v3_paula_mkt",
                    "Every other holder of this HIGH pricing DB is in Revenue Management; she is in Marketing.",
                ),
            ),
            build=_v3_hotel_rate_outlier,
            split=FRESH,
        ),
        Scenario(
            name="v3_radiology_failed_burst",
            description="Failed-login burst, then success, then bulk read of the imaging archive.",
            expected=(
                ExpectedFinding(
                    "ANOMALOUS_BEHAVIOR", "v3_owen_radtech",
                    "24 failed logins in ~12 minutes then 180 reads in 40 minutes, against ~3 reads a day of history.",
                ),
                # Triage (2026-10-03): the cross-rule sequence stage was built
                # after the FRESH v3 read and fired here unlabelled. The author's
                # own description is a staged intrusion, so the truth is
                # positive. Not part of the quoted reading.
                ExpectedFinding(
                    "MULTI_STAGE_SEQUENCE", "v3_owen_radtech",
                    "Triage after the read: a credential burst and, minutes later, a bulk "
                    "read of radiology records -- one incident.",
                ),
            ),
            build=_v3_radiology_failed_burst,
            split=FRESH,
        ),
        Scenario(
            name="v3_payroll_cycles",
            description="Payroll export's monthly bulk read matches its history; an analyst's sudden bulk read does not.",
            expected=(
                ExpectedFinding(
                    "ANOMALOUS_BEHAVIOR", "v3_svc_payroll_export",
                    "Its 60-read burst recurs every pay cycle; this one matches its own history.",
                    should_fire=False,
                ),
                ExpectedFinding(
                    "ANOMALOUS_BEHAVIOR", "v3_dmitri_payroll",
                    "150 reads in under an hour against a history of two or three a day.",
                ),
            ),
            build=_v3_payroll_cycles,
            split=FRESH,
        ),
        Scenario(
            name="v3_k12_annual_rollover",
            description="Yearly enrollment rollover service, silent for ~11 months as every year.",
            expected=(
                ExpectedFinding(
                    "STALE_ACCESS", "v3_svc_enroll_rollover",
                    "It runs once a year and has for four years; eleven months of quiet is its rhythm.",
                    should_fire=False,
                ),
            ),
            build=_v3_k12_annual_rollover,
            split=FRESH,
        ),
        Scenario(
            name="v3_telehealth_public",
            description="Standing admin on a public critical patient API; external agency admin on a public LOW brochure site.",
            expected=(
                ExpectedFinding(
                    "EXTERNAL_EXPOSURE", "v3_svc_portal_deployer",
                    "Standing deploy/admin on an internet-facing critical system holding patient records.",
                ),
                ExpectedFinding(
                    "EXCESSIVE_PRIVILEGE", "v3_svc_portal_deployer",
                    "Triage after the read (2026-10-01): standing admin and deploy on a CRITICAL system.",
                ),
                ExpectedFinding(
                    "CONTEXT_MISMATCH", "v3_svc_portal_deployer",
                    "Triage after the read (2026-10-01): the logins are the CI pipeline authenticating, as the "
                    "author wrote it, not people. The event vocabulary cannot tell a "
                    "programmatic sign-in from an interactive one -- a data-model gap.",
                    should_fire=False,
                ),
                ExpectedFinding(
                    "EXTERNAL_EXPOSURE", "v3_mo_web_agency",
                    "External and public, but the site is LOW value; nothing that matters is exposed.",
                    should_fire=False,
                ),
            ),
            build=_v3_telehealth_public,
            split=FRESH,
        ),
    )
