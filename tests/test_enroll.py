import dataclasses

import pytest

from mayfly.identity import (Confirm, DeviceEnrollment, EnrollmentError, EnrollmentToken, Hello,
                             Response)
from mayfly.identity.keys import is_zero
from mayfly.identity.session import SessionState
from mayfly.keystore import TenantKeyStore

from conftest import FAST, enroll


def test_handshake_agrees_on_k0(store_a):
    tok = store_a.issue_token()
    dev = DeviceEnrollment(tok)
    resp = store_a.handle_hello(Hello.from_bytes(dev.hello().to_bytes()), 0.0)
    confirm, k0_dev = dev.finish(Response.from_bytes(resp.to_bytes()))
    label = store_a.handle_confirm(Confirm.from_bytes(confirm.to_bytes()), 0.0)
    [(e, k0_mon)] = store_a.get(label).live_keys()
    assert e == 0 and k0_mon == k0_dev and not is_zero(k0_dev)
    assert store_a.get(label).state is SessionState.ACTIVE


def test_wrong_token_fails(store_a):
    tok = store_a.issue_token()
    forged = EnrollmentToken(tok.tenant_id, tok.token_id, b"\x00" * 32)
    with pytest.raises(EnrollmentError):
        store_a.handle_hello(DeviceEnrollment(forged).hello(), 0.0)
    assert len(store_a) == 0


def test_unknown_token_id_fails(store_a):
    store_a.issue_token()
    stray = EnrollmentToken(b"tenant-A", b"\x01" * 8, b"\x02" * 32)
    with pytest.raises(EnrollmentError):
        store_a.handle_hello(DeviceEnrollment(stray).hello(), 0.0)


def test_token_is_single_use(store_a):
    tok = store_a.issue_token()
    for attempt in range(2):
        dev = DeviceEnrollment(tok)
        if attempt == 0:
            resp = store_a.handle_hello(dev.hello(), 0.0)
            store_a.handle_confirm(dev.finish(resp)[0], 0.0)
        else:
            with pytest.raises(EnrollmentError):
                store_a.handle_hello(dev.hello(), 0.0)


def test_token_from_other_tenant_rejected(store_a, store_b):
    tok_b = store_b.issue_token()
    with pytest.raises(EnrollmentError):
        store_a.handle_hello(DeviceEnrollment(tok_b).hello(), 0.0)


def test_device_rejects_tampered_response(store_a):
    tok = store_a.issue_token()
    dev = DeviceEnrollment(tok)
    resp = store_a.handle_hello(dev.hello(), 0.0)
    bad = dataclasses.replace(resp, monitor_pub=bytes(32 - 1) + b"\x09")
    with pytest.raises(EnrollmentError):
        dev.finish(bad)


def test_device_rejects_impostor_monitor():
    # An impostor that knows the token id but not the secret cannot answer.
    real = TenantKeyStore(b"tenant-A", FAST)
    tok = real.issue_token()
    impostor = TenantKeyStore(b"tenant-A", FAST)
    fake = EnrollmentToken(tok.tenant_id, tok.token_id, b"\x07" * 32)
    impostor._tokens[fake.token_id] = fake
    dev = DeviceEnrollment(tok)
    with pytest.raises(EnrollmentError):
        impostor.handle_hello(dev.hello(), 0.0)  # device MAC fails at impostor too
    # and a response MAC'd under the wrong secret is rejected by the device
    dev2 = DeviceEnrollment(fake)
    resp = impostor.handle_hello(dev2.hello(), 0.0)
    with pytest.raises(EnrollmentError):
        DeviceEnrollment(tok).finish(resp)


def test_bad_confirm_kills_pending_session(store_a):
    tok = store_a.issue_token()
    dev = DeviceEnrollment(tok)
    store_a.handle_hello(dev.hello(), 0.0)
    with pytest.raises(EnrollmentError):
        store_a.handle_confirm(Confirm(tok.token_id, b"\x00" * 32), 0.0)
    assert len(store_a) == 0
    # the token was not spent, so a genuine retry still works
    dev = DeviceEnrollment(tok)
    resp = store_a.handle_hello(dev.hello(), 1.0)
    label = store_a.handle_confirm(dev.finish(resp)[0], 1.0)
    assert store_a.get(label) is not None


def test_pending_enrollment_times_out(store_a):
    tok = store_a.issue_token()
    dev = DeviceEnrollment(tok)
    resp = store_a.handle_hello(dev.hello(), 0.0)
    confirm, _ = dev.finish(resp)
    store_a.tick(FAST.enroll_timeout_seconds)
    with pytest.raises(EnrollmentError):
        store_a.handle_confirm(confirm, FAST.enroll_timeout_seconds)


def test_malformed_messages_rejected():
    for cls in (Hello, Response, Confirm):
        with pytest.raises(EnrollmentError):
            cls.from_bytes(b"\x01garbage")


def test_new_session_gets_unrelated_label(store_a):
    labels = [enroll(store_a, float(i))[0] for i in range(50)]
    assert len(set(labels)) == 50
    assert all(len(bytes.fromhex(l)) == 6 for l in labels)
