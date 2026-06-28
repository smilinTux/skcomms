"""Tests for the optional sk_pqc re-export shim (coord 0a1f0a51).

Each skcomms PQC primitive module (pqkem, pqdm, pqroute, anon_queue,
crypto_suites) carries a guarded shim: when the published ``sk_pqc`` package is
installed the module re-exports its vetted primitives (``_SK_PQC_BACKED`` True);
on boxes WITHOUT sk-pqc (e.g. .41) the import fails and the UNCHANGED local
definitions are used (``_SK_PQC_BACKED`` False). Behaviour is byte-identical
either way — these tests pin both legs.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys

import pytest


# --- isolated loader: exec a module fresh, optionally blocking sk_pqc ---------
class _BlockSkPqc:
    """meta_path finder that makes ``import sk_pqc[...]`` fail (simulates .41)."""

    def find_spec(self, name, path=None, target=None):  # noqa: D401, ANN001
        if name == "sk_pqc" or name.startswith("sk_pqc."):
            raise ImportError("sk_pqc blocked for fallback test")
        return None


def _load_isolated(mod_dotted: str, *, block_skpqc: bool):
    """Exec ``mod_dotted`` afresh from its source file into a throwaway name.

    With ``block_skpqc`` the sk_pqc import is forced to fail so the module's
    local fallback definitions execute (``_SK_PQC_BACKED`` False).
    """
    real = sys.modules.get(mod_dotted) or importlib.import_module(mod_dotted)
    path = real.__file__
    name = "_iso_" + mod_dotted.replace(".", "_") + ("_no" if block_skpqc else "_yes")
    blocker = _BlockSkPqc() if block_skpqc else None
    saved: dict[str, object] = {}
    if blocker is not None:
        sys.meta_path.insert(0, blocker)
        for k in list(sys.modules):
            if k == "sk_pqc" or k.startswith("sk_pqc."):
                saved[k] = sys.modules.pop(k)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        # Preserve the real package so the module's relative imports (e.g.
        # ``from .pqkem import ...``) resolve to the installed package.
        m.__package__ = mod_dotted.rsplit(".", 1)[0]
        sys.modules[name] = m
        spec.loader.exec_module(m)
        return m
    finally:
        if blocker is not None:
            sys.meta_path.remove(blocker)
            sys.modules.update(saved)
        sys.modules.pop(name, None)


# Module under test -> (a key public symbol used for the identity assertion)
_MODS = {
    "pqkem": "hybrid_encap",
    "pqdm": "seal",
    "pqroute": "seal_routed",
    "anon_queue": "encode_aqid",
    "crypto_suites": "get_suite",
}


@pytest.mark.parametrize("mod_name,symbol", list(_MODS.items()))
def test_backed_when_skpqc_present(mod_name, symbol):
    """With sk_pqc importable, the module IS the published lib (symbol identity)."""
    sk_pqc = pytest.importorskip("sk_pqc")  # skip on boxes without sk-pqc (.41)
    pub = importlib.import_module(f"sk_pqc.{mod_name}")
    local = importlib.import_module(f"skcomms.{mod_name}")
    assert getattr(local, "_SK_PQC_BACKED") is True
    # Key-symbol identity: the local module's symbol IS the published object.
    assert getattr(local, symbol) is getattr(pub, symbol)


@pytest.mark.parametrize("mod_name,symbol", list(_MODS.items()))
def test_fallback_when_skpqc_absent(mod_name, symbol):
    """Simulated absence: local definitions are used and remain functional."""
    m = _load_isolated(f"skcomms.{mod_name}", block_skpqc=True)
    assert getattr(m, "_SK_PQC_BACKED") is False
    # The fallback symbol exists and is callable (local definition, not published).
    assert callable(getattr(m, symbol))


def test_fallback_pqkem_roundtrip():
    """The local pqkem fallback performs a real hybrid encap/decap round-trip."""
    m = _load_isolated("skcomms.pqkem", block_skpqc=True)
    assert m._SK_PQC_BACKED is False
    kp = m.hybrid_keypair()
    ct, ss_enc = m.hybrid_encap(kp.public_key)
    ss_dec = m.hybrid_decap(ct, kp.private_key)
    assert ss_enc == ss_dec
    assert m.PUBLIC_KEY_LEN == 1216
    assert m.SUITE_ID == "x25519-mlkem768"


def test_behavior_identical_anon_queue():
    """encode_aqid + auth_tag are byte-identical backed vs fallback."""
    backed = importlib.import_module("skcomms.anon_queue")
    fb = _load_isolated("skcomms.anon_queue", block_skpqc=True)
    relay, sid = "relay.skworld.io", bytes(range(16))
    assert backed.encode_aqid(relay, sid) == fb.encode_aqid(relay, sid)
    secret, msg, nonce = b"s" * 32, b"hello-anon", b"n" * 16
    assert backed.auth_tag(secret, msg, nonce) == fb.auth_tag(secret, msg, nonce)


def test_behavior_identical_crypto_suites():
    """Suite registry answers identically backed vs fallback."""
    backed = importlib.import_module("skcomms.crypto_suites")
    fb = _load_isolated("skcomms.crypto_suites", block_skpqc=True)
    sid = "x25519-mlkem768"
    assert backed.is_quantum_resistant(sid) == fb.is_quantum_resistant(sid)
    assert backed.suite_status(sid) == fb.suite_status(sid)
    assert backed.get_suite(sid).suite_id == fb.get_suite(sid).suite_id
