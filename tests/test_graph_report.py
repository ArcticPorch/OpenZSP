"""
The graph CLI views: `--paths <identity>` and `--blast-radius`.

They only format numbers the rules already compute, so these tests pin the
shape of the output and that it agrees with those functions.
"""

import re
import sys

import pytest

from app import main as cli
from app.connectors.synthetic import SyntheticConnector
from app.normalize.normalizer import Normalizer
from app.risk.graph_report import format_blast_radius, format_paths
from tests.test_normalize import ANCHOR


@pytest.fixture(scope="module")
def estate():
    return Normalizer().normalize(SyntheticConnector(anchor_time=ANCHOR).collect())


def test_paths_shows_the_route_as_a_readable_chain(estate):
    out = format_paths(estate, "petra", ANCHOR)
    assert "petra (human, external)" in out
    assert "support_crm_db  [admin, 2 hops, standing]" in out
    assert "petra -impersonate-> helpdesk_tier2_role =becomes=> role_helpdesk_tier2 -admin-> support_crm_db" in out
    assert "role_helpdesk_tier2  [1 hop, standing]" in out


def test_paths_lists_stepping_stones_apart_from_the_score(estate):
    out = format_paths(estate, "vesna", ANCHOR)
    assert re.search(r"standing\s+30\.0  over 1 resource", out)
    assert "stepping-stones (not counted): bcast_cdn_config_role" in out
    principals = re.findall(r"  (role_bcast_\w+)  \[(\d) hop", out)
    assert [int(h) for _, h in principals] == [1, 2, 3, 4, 5]  # nearest first


def test_paths_for_an_identity_with_no_routes(estate):
    out = format_paths(estate, "iris", ANCHOR)
    assert "Routes to crown jewels it holds no grant on (0):\n  none" in out


def test_paths_rejects_an_unknown_identity(estate):
    with pytest.raises(KeyError):
        format_paths(estate, "nobody", ANCHOR)


def test_blast_radius_ranks_by_standing_score(estate):
    out = format_blast_radius(estate, ANCHOR, top=10)
    rows = re.findall(r"^  (\S+)\s+(\d+\.\d)\s+\d+\.\d\s+\d+\.\d  ", out, re.MULTILINE)
    assert len(rows) == 10
    scores = [float(s) for _, s in rows]
    assert scores == sorted(scores, reverse=True)
    assert rows[0][0] == "svc_ci_runner"


def test_blast_radius_ends_with_the_choke_points(estate):
    out = format_blast_radius(estate, ANCHOR)
    choke = out.split("Choke points")[1]
    first = choke.splitlines()[2]
    assert first.split()[0] in {"becomes:adjuster_role", "g_role_adjuster_payments"}
    assert "cuts 3: adaeze -> claims_payment_db" in first


def test_cli_dispatches_both_views(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["app.main", "--paths", "gustav"])
    assert cli.main() == 0
    assert "~governs~> treasury_payments_ledger" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["app.main", "--blast-radius"])
    assert cli.main() == 0
    assert "Choke points" in capsys.readouterr().out


def test_cli_unknown_identity_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["app.main", "--paths", "nobody"])
    assert cli.main() == 2
    assert "unknown identity 'nobody'" in capsys.readouterr().err
