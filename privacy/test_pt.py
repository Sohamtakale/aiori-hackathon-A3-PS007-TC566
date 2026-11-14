"""PT-1..PT-5 pass criteria (PRD section 12). Collected by pytest (testpaths includes privacy/)."""
import pytest
from privacy import pt


@pytest.mark.parametrize("fn", pt.ALL, ids=[f.__name__ for f in pt.ALL])
def test_privacy_criterion(fn):
    r = fn()
    assert r.passed, "%s failed: %s" % (r.name, r.detail)


def test_pt1_no_key_material_after_expiry():
    r = pt.pt1_expiry()
    assert r.metrics["still_resolve"] == 0 and r.metrics["live_key_buffers"] == 0


def test_pt2_zero_cross_tenant():
    assert pt.pt2_cross_tenant().metrics["false_resolves"] == 0


def test_pt3_concurrent_overlap_near_random():
    r = pt.pt3_linkability()
    assert r.metrics["hard_advantage"] <= 0.20


def test_pt4_no_addresses_in_logs():
    r = pt.pt4_log_hygiene()
    assert r.metrics["addresses_found"] == 0 and r.metrics["alerts"] > 0


def test_pt5_forward_secrecy():
    assert pt.pt5_forward_secrecy().metrics["still_resolve"] == 0
