"""Tests for the Sigstore release-signature verifier (specora_verify.release).

Focus: lock in the sigstore >= 3.0 verification contract. release.py is
release-orchestration tooling that isn't otherwise exercised by the suite, and
a sigstore API drift (the pre-2.0 ``Verifier.verify(materials=...)`` signature
was removed in 3.x in favour of ``verify_artifact``) shipped undetected until
``mypy --strict`` caught it. These tests are the runtime guard so it can't
regress silently again.

The sigstore network/TUF machinery is mocked — the point is to assert the
*shape* of the call (verify_artifact, not verify) and the result mapping, not
to exercise real cryptography.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("sigstore")


def test_real_verifier_exposes_verify_artifact() -> None:
    """Contract guard: the pinned sigstore must expose the 3.x verify API.

    If sigstore renames/removes this again, fail loudly here rather than at
    release time.
    """
    from sigstore.verify import Verifier

    assert hasattr(Verifier, "verify_artifact"), (
        "sigstore Verifier lost verify_artifact — release.py needs porting"
    )
    assert not hasattr(Verifier, "verify"), (
        "sigstore re-introduced Verifier.verify — revisit release.py"
    )


class _FakeVerifier:
    """Stand-in for sigstore Verifier. Deliberately has NO verify() method, so
    a regression to the old API surfaces as an AttributeError."""

    last_call: dict = {}

    @classmethod
    def production(cls) -> _FakeVerifier:
        return cls()

    def verify_artifact(self, input_, bundle, policy) -> None:
        _FakeVerifier.last_call = {
            "input_": input_,
            "bundle": bundle,
            "policy": policy,
        }


def _fake_bundle_factory(*, signing_certificate=None, tlog_entries=()):
    class _FakeBundle:
        @staticmethod
        def from_json(_text: str) -> _FakeBundle:
            return _FakeBundle()

    inst = _FakeBundle()
    inst.signing_certificate = signing_certificate
    inst._inner = SimpleNamespace(
        verification_material=SimpleNamespace(tlog_entries=list(tlog_entries))
    )
    return _FakeBundle, inst


def _patch_sigstore(monkeypatch, verifier_cls, bundle_cls) -> None:
    import sigstore.models
    import sigstore.verify

    monkeypatch.setattr(sigstore.verify, "Verifier", verifier_cls)
    monkeypatch.setattr(sigstore.models, "Bundle", bundle_cls)


def test_verify_calls_verify_artifact_with_file_content(monkeypatch, tmp_path) -> None:
    artifact = tmp_path / "specora_verify-1.0.0.whl"
    artifact.write_bytes(b"wheel-bytes")
    (tmp_path / "specora_verify-1.0.0.whl.sigstore.json").write_text("{}")

    bundle_cls, bundle_inst = _fake_bundle_factory(tlog_entries=[])
    bundle_cls.from_json = staticmethod(lambda _t: bundle_inst)  # type: ignore[method-assign]
    _patch_sigstore(monkeypatch, _FakeVerifier, bundle_cls)
    _FakeVerifier.last_call = {}

    from specora_verify.release import verify_sigstore_signature

    ok, log_index, err = verify_sigstore_signature(artifact, "1.0.0")

    assert ok is True, err
    assert err is None
    assert log_index is None  # no tlog entries on the fake bundle
    # The load-bearing assertion: we went through verify_artifact, and it
    # received the raw file bytes as input_.
    assert _FakeVerifier.last_call["input_"] == b"wheel-bytes"
    assert _FakeVerifier.last_call["bundle"] is bundle_inst


def test_verify_maps_verification_failure_to_false(monkeypatch, tmp_path) -> None:
    artifact = tmp_path / "specora_verify-1.0.0.whl"
    artifact.write_bytes(b"wheel-bytes")
    (tmp_path / "specora_verify-1.0.0.whl.sigstore.json").write_text("{}")

    from sigstore.errors import VerificationError

    class _FailingVerifier(_FakeVerifier):
        def verify_artifact(self, input_, bundle, policy) -> None:
            raise VerificationError("identity policy mismatch")

    bundle_cls, bundle_inst = _fake_bundle_factory()
    bundle_cls.from_json = staticmethod(lambda _t: bundle_inst)  # type: ignore[method-assign]
    _patch_sigstore(monkeypatch, _FailingVerifier, bundle_cls)

    from specora_verify.release import verify_sigstore_signature

    ok, log_index, err = verify_sigstore_signature(artifact, "1.0.0")

    assert ok is False
    assert log_index is None
    assert err and "identity policy mismatch" in err


def test_verify_reports_missing_bundle(monkeypatch, tmp_path) -> None:
    artifact = tmp_path / "specora_verify-1.0.0.whl"
    artifact.write_bytes(b"wheel-bytes")
    # No .sigstore.json next to it.

    _patch_sigstore(monkeypatch, _FakeVerifier, _fake_bundle_factory()[0])

    from specora_verify.release import verify_sigstore_signature

    ok, log_index, err = verify_sigstore_signature(artifact, "1.0.0")

    assert ok is False
    assert err and "Signature bundle not found" in err
