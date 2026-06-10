# QR Device-Pairing — Implementation Plan (core backend, task 238ede04)

> Reuses the skcomms peer registry (`PeerRecord`), `peers.add_peer`, `tofu`, `key_exchange`, and `identity.resolve_self_identity`. Pure-Python QR via `segno` (installed). Web generator/scanner UI (0aa959f0/ce5fdd90), WebRTC session (7f28ac51), Tailscale-Funnel public pairing (2ab5aa6c) are SEPARATE follow-on tasks — NOT this plan.

**Goal:** pair with another agent by QR. `skcomms pair show` prints a QR (+`skp://` URI); the peer's `skcomms pair accept <uri|file>` verifies + adds them. **Compact by default** (fingerprint + connectivity hints, fetch pubkey on accept), **`--embed-key`** for a self-contained offline QR (Chef's call: "both").

**Tech Stack:** Python 3.12, Pydantic v2, segno (QR), Click (CLI), pytest. Repo `/home/cbrd21/clawd/skcapstone-repos/skcomms` (branch `feat/qr-pairing`).

**Conventions:** TDD (fail→impl→pass→commit). `~/.skenv/bin/python -m pytest ... -p no:cacheprovider`. Explicit `git add` (never `-A`). Commit messages end with `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`. Do NOT push. Tests standalone (tmp `SKCOMMS_HOME`, in-process pgpy keys, injected fetcher — no network).

**APIs to reuse (confirmed):**
- `skcomms.identity.resolve_self_identity(agent=None) -> dict` (keys incl. `fqid`, `fingerprint`, `capauth_uri`).
- `skcomms.registry.PeerRecord` (fqid, pgp_fingerprint, pubkey, syncthing_device_id, tailscale, https) + `PeerRegistry.from_config().resolve(fqid)`.
- `skcomms.peers.add_peer(fqid, syncthing_device_id, pubkey_path, ...)` (TOFU-binds, derives fingerprint from the pubkey, refuses CONFLICT), `skcomms.peers.fingerprint_from_pubkey(armor) -> str`.
- `skcomms.tofu.verify_fingerprint(fqid, fingerprint)`.
- `skcomms.key_exchange.fetch_peer_from_did(handle_or_url, ...)` (returns a peer dict incl. armored pubkey), `export_peer_bundle()`.
- `skcomms.home.skcomms_home()` (honors `SKCOMMS_HOME`).

---

## Task 1: `PairingBundle` + `skp://` URI encode/decode

**Files:** Create `src/skcomms/pairing.py`. Test: `tests/test_pairing.py`.

- [ ] **Step 1 — failing tests** (`tests/test_pairing.py`):
```python
from skcomms.pairing import PairingBundle, to_skp_uri, parse_skp_uri

def test_uri_round_trip_compact():
    b = PairingBundle(fqid="lumina@chef.skworld", fingerprint="AB"*20,
                      syncthing_device_id="DEV-1", tailscale="lumina.ts.net",
                      https="https://x/peers.json")
    uri = to_skp_uri(b)
    assert uri.startswith("skp://pair?")
    assert parse_skp_uri(uri) == b

def test_uri_round_trip_embedded_key():
    b = PairingBundle(fqid="opus@chef.skworld", fingerprint="CD"*20,
                      pubkey="-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END-----\n")
    assert parse_skp_uri(to_skp_uri(b)).pubkey == b.pubkey

def test_parse_rejects_non_skp():
    import pytest
    with pytest.raises(ValueError):
        parse_skp_uri("https://evil/pair?fqid=x")

def test_bundle_requires_fqid_and_fingerprint():
    import pytest
    with pytest.raises(Exception):
        PairingBundle(fqid="", fingerprint="")
```

- [ ] **Step 2 — run, confirm fail:** `~/.skenv/bin/python -m pytest tests/test_pairing.py -q` → ImportError.

- [ ] **Step 3 — implement** `src/skcomms/pairing.py`:
```python
"""QR device-pairing — encode an agent's pairing bundle to a skp:// URI/QR and
accept a scanned one (verify fingerprint via TOFU, add the peer)."""
from __future__ import annotations

import base64
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)
SKP_SCHEME = "skp"

class PairingBundle(BaseModel):
    fqid: str
    fingerprint: str                       # 40-hex (or test value); canonical id
    syncthing_device_id: Optional[str] = None
    tailscale: Optional[str] = None
    https: Optional[str] = None
    pubkey: Optional[str] = None           # armored, only when --embed-key

    @field_validator("fqid", "fingerprint")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("fqid and fingerprint are required")
        return v

def to_skp_uri(b: PairingBundle) -> str:
    params = {"v": "1", "fqid": b.fqid, "fp": b.fingerprint}
    if b.syncthing_device_id: params["sy"] = b.syncthing_device_id
    if b.tailscale: params["ts"] = b.tailscale
    if b.https: params["https"] = b.https
    if b.pubkey:
        params["pk"] = base64.urlsafe_b64encode(b.pubkey.encode()).decode()
    return f"{SKP_SCHEME}://pair?" + urlencode(params)

def parse_skp_uri(uri: str) -> PairingBundle:
    u = urlparse(uri)
    if u.scheme != SKP_SCHEME or u.netloc != "pair":
        raise ValueError(f"not an skp pairing URI: {uri!r}")
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    pk = q.get("pk")
    pubkey = base64.urlsafe_b64decode(pk.encode()).decode() if pk else None
    return PairingBundle(fqid=q.get("fqid", ""), fingerprint=q.get("fp", ""),
                         syncthing_device_id=q.get("sy"), tailscale=q.get("ts"),
                         https=q.get("https"), pubkey=pubkey)
```

- [ ] **Step 4 — run, confirm pass:** `~/.skenv/bin/python -m pytest tests/test_pairing.py -q` → PASS.

- [ ] **Step 5 — commit:**
```bash
git add src/skcomms/pairing.py tests/test_pairing.py
git commit -m "feat(pairing): PairingBundle + skp:// URI encode/decode

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: build-from-self + QR rendering (segno)

**Files:** Modify `src/skcomms/pairing.py`. Test: `tests/test_pairing.py`.

- [ ] **Step 1 — failing tests:**
```python
def test_bundle_from_self(monkeypatch, tmp_path):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "resolve_self_identity",
        lambda agent=None: {"fqid": "lumina@chef.skworld", "fingerprint": "AB"*20})
    monkeypatch.setattr(P, "_self_hints", lambda fqid: {"syncthing_device_id": "DEV-9"})
    b = P.bundle_from_self()
    assert b.fqid == "lumina@chef.skworld"
    assert b.syncthing_device_id == "DEV-9"
    assert b.pubkey is None

def test_bundle_from_self_embed_key(monkeypatch):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "resolve_self_identity",
        lambda agent=None: {"fqid": "lumina@chef.skworld", "fingerprint": "AB"*20})
    monkeypatch.setattr(P, "_self_hints", lambda fqid: {})
    monkeypatch.setattr(P, "_self_pubkey_armor", lambda: "-----BEGIN PGP-----\nx\n-----END-----\n")
    b = P.bundle_from_self(embed_key=True)
    assert b.pubkey and "PGP" in b.pubkey

def test_make_qr_returns_uri_and_renders():
    from skcomms.pairing import PairingBundle, make_pairing_qr
    uri, qr = make_pairing_qr(PairingBundle(fqid="a@b.c", fingerprint="AB"*20))
    assert uri.startswith("skp://pair?")
    assert qr.terminal()  # segno QRCode renders ASCII without error (truthy str)
```

- [ ] **Step 2 — confirm fail.**

- [ ] **Step 3 — implement** (add to pairing.py):
```python
# graceful imports — keep the module importable even if deps shift
try:
    from .identity import resolve_self_identity
except Exception:  # noqa: BLE001
    def resolve_self_identity(agent=None): return {}

def _self_hints(fqid: str) -> dict:
    """Connectivity hints for *fqid* from the peer registry (best-effort)."""
    try:
        from .registry import PeerRegistry
        rec = PeerRegistry.from_config().resolve(fqid)
        if rec is None:
            return {}
        return {k: v for k, v in {
            "syncthing_device_id": rec.syncthing_device_id,
            "tailscale": (rec.tailscale or {}).get("magicdns") if isinstance(rec.tailscale, dict) else rec.tailscale,
            "https": rec.https,
        }.items() if v}
    except Exception as exc:  # noqa: BLE001
        logger.debug("self hints unavailable: %s", exc)
        return {}

def _self_pubkey_armor() -> Optional[str]:
    """This agent's armored public key (for --embed-key), best-effort."""
    try:
        from .key_exchange import export_peer_bundle
        bundle = export_peer_bundle()
        return bundle.get("pubkey") if isinstance(bundle, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("self pubkey unavailable: %s", exc)
        return None

def bundle_from_self(agent: Optional[str] = None, *, embed_key: bool = False) -> PairingBundle:
    ident = resolve_self_identity(agent) or {}
    fqid = ident.get("fqid") or ""
    fp = ident.get("fingerprint") or ""
    hints = _self_hints(fqid)
    pubkey = _self_pubkey_armor() if embed_key else None
    return PairingBundle(fqid=fqid, fingerprint=fp, pubkey=pubkey, **hints)

def make_pairing_qr(bundle: PairingBundle):
    """Return (skp_uri, segno.QRCode). Caller can .save(path) or .terminal()."""
    import segno
    uri = to_skp_uri(bundle)
    return uri, segno.make(uri, error="m")
```

- [ ] **Step 4 — confirm pass.**
- [ ] **Step 5 — commit:** `feat(pairing): bundle-from-self + segno QR rendering` (same trailer).

---

## Task 3: `accept_pairing` (verify fingerprint → add peer)

**Files:** Modify `src/skcomms/pairing.py`. Test: `tests/test_pairing.py`.

- [ ] **Step 1 — failing tests:** (use in-process pgpy keys + an injected fetcher; tmp SKCOMMS_HOME via monkeypatch)
```python
def _gen_pubkey():
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    k = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("t", email="t@x")
    k.add_uid(uid, usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256],
              ciphers=[SymmetricKeyAlgorithm.AES256], compression=[CompressionAlgorithm.ZLIB])
    return str(k.pubkey)

def test_accept_embedded_key_adds_peer(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    from skcomms.peers import fingerprint_from_pubkey
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-2", pubkey=pub))
    rec = accept_pairing(uri)
    assert rec["fqid"] == "opus@chef.skworld"
    # appears in the peer store
    from skcomms.peers import list_peers
    assert any(p.get("fqid") == "opus@chef.skworld" or "opus@chef.skworld" in str(p) for p in [list_peers()] )

def test_accept_compact_fetches_then_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    from skcomms.peers import fingerprint_from_pubkey
    pub = _gen_pubkey(); fp = fingerprint_from_pubkey(pub)
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint=fp,
                                   syncthing_device_id="DEV-3"))  # no embedded key
    rec = accept_pairing(uri, fetcher=lambda b: pub)   # injected: returns the pubkey
    assert rec["fqid"] == "opus@chef.skworld"

def test_accept_rejects_fingerprint_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import pytest
    from skcomms.pairing import PairingBundle, to_skp_uri, accept_pairing
    other = _gen_pubkey()
    uri = to_skp_uri(PairingBundle(fqid="opus@chef.skworld", fingerprint="00"*20,
                                   syncthing_device_id="D", pubkey=other))
    with pytest.raises(ValueError):
        accept_pairing(uri)   # embedded key's fingerprint != claimed fingerprint
```

- [ ] **Step 2 — confirm fail.**

- [ ] **Step 3 — implement** (add to pairing.py):
```python
def _default_fetcher(bundle: "PairingBundle") -> Optional[str]:
    """Fetch the peer's armored pubkey via its hints (best-effort, no network in tests)."""
    try:
        from .key_exchange import fetch_peer_from_did
        target = bundle.https or bundle.fqid.split("@")[0]
        peer = fetch_peer_from_did(target)
        return peer.get("pubkey") if isinstance(peer, dict) else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("pubkey fetch failed: %s", exc)
        return None

def accept_pairing(uri_or_path: str, *, fetcher=None) -> dict:
    """Accept a scanned skp:// URI (or a file containing one): verify the peer's
    key fingerprint against the bundle, then TOFU-add the peer. Returns a summary
    dict. Raises ValueError on a fingerprint mismatch or unresolvable key."""
    import os, tempfile
    from pathlib import Path
    from .peers import add_peer, fingerprint_from_pubkey
    text = uri_or_path
    p = Path(uri_or_path)
    if not uri_or_path.startswith(f"{SKP_SCHEME}://") and p.exists():
        text = p.read_text(encoding="utf-8").strip()
    bundle = parse_skp_uri(text)
    pubkey = bundle.pubkey or (fetcher or _default_fetcher)(bundle)
    if not pubkey:
        raise ValueError(f"could not resolve a public key for {bundle.fqid}")
    actual_fp = fingerprint_from_pubkey(pubkey)
    if actual_fp.upper() != bundle.fingerprint.upper():
        raise ValueError(
            f"fingerprint mismatch for {bundle.fqid}: QR claims {bundle.fingerprint}, "
            f"key is {actual_fp} — refusing to pair")
    # write the pubkey to a temp file for peers.add_peer (which reads a path)
    fd, tmp = tempfile.mkstemp(suffix=".asc"); os.close(fd)
    try:
        Path(tmp).write_text(pubkey, encoding="utf-8")
        add_peer(bundle.fqid, bundle.syncthing_device_id or "", tmp)
    finally:
        os.unlink(tmp)
    return {"fqid": bundle.fqid, "fingerprint": actual_fp,
            "syncthing_device_id": bundle.syncthing_device_id,
            "transport_hints": {k: getattr(bundle, k) for k in ("tailscale", "https") if getattr(bundle, k)}}
```
Note: if `add_peer` requires a non-empty `syncthing_device_id`, and the bundle has none, pass a placeholder or adjust — read add_peer first and match its contract (a compact QR may legitimately have only a tailscale/https hint; if add_peer needs a device id, store the binding via tofu.record_fingerprint + a peers.json entry instead). Keep the fingerprint-verify-before-add invariant regardless.

- [ ] **Step 4 — confirm pass** (`tests/test_pairing.py` all green; also run `tests/test_peers.py tests/test_tofu.py` — no regression).
- [ ] **Step 5 — commit:** `feat(pairing): accept_pairing — verify fingerprint then TOFU-add peer` (trailer).

---

## Task 4: `skcomms pair` CLI (`show` / `accept`)

**Files:** Modify `src/skcomms/cli.py`. Test: `tests/test_pairing_cli.py`.

- [ ] **Step 1 — failing tests:**
```python
from click.testing import CliRunner
from skcomms import cli

def test_pair_show_prints_uri(monkeypatch):
    import skcomms.pairing as P
    monkeypatch.setattr(P, "bundle_from_self",
        lambda agent=None, embed_key=False: P.PairingBundle(fqid="a@b.c", fingerprint="AB"*20))
    r = CliRunner().invoke(cli.main, ["pair", "show"])
    assert r.exit_code == 0, r.output
    assert "skp://pair?" in r.output

def test_pair_accept_invokes_accept(monkeypatch, tmp_path):
    monkeypatch.setenv("SKCOMMS_HOME", str(tmp_path))
    import skcomms.pairing as P
    seen = {}
    monkeypatch.setattr(P, "accept_pairing",
        lambda src, **kw: seen.setdefault("src", src) or {"fqid": "x@y.z", "fingerprint": "F"})
    r = CliRunner().invoke(cli.main, ["pair", "accept", "skp://pair?v=1&fqid=x@y.z&fp=F"])
    assert r.exit_code == 0, r.output
    assert seen["src"].startswith("skp://pair?")
    assert "x@y.z" in r.output
```

- [ ] **Step 2 — confirm fail.**

- [ ] **Step 3 — implement:** add a `pair` Click group to cli.py (mirror the existing `peers`/`registry` groups):
```python
@main.group("pair")
def pair_group():
    """QR device-pairing: show your invite, accept a scanned one."""

@pair_group.command("show")
@click.option("--embed-key", is_flag=True, help="Embed the full public key (self-contained, offline; larger QR).")
@click.option("-o", "--out", type=click.Path(), default=None, help="Save the QR to a .png/.svg file.")
@click.option("-a", "--agent", default=None, help="Agent name (default: resolved self).")
def pair_show(embed_key, out, agent):
    from .pairing import bundle_from_self, make_pairing_qr
    bundle = bundle_from_self(agent, embed_key=embed_key)
    uri, qr = make_pairing_qr(bundle)
    click.echo(qr.terminal(compact=True))
    click.echo(uri)
    if out:
        qr.save(out)
        click.echo(f"saved QR -> {out}")

@pair_group.command("accept")
@click.argument("source")  # an skp:// URI or a file path containing one
def pair_accept(source):
    from .pairing import accept_pairing
    res = accept_pairing(source)
    click.echo(f"paired with {res['fqid']} (fingerprint {res['fingerprint']})")
```

- [ ] **Step 4 — confirm pass** (`tests/test_pairing_cli.py`).
- [ ] **Step 5 — commit:** `feat(cli): skcomms pair show/accept (QR device-pairing)` (trailer).

---

## Task 5: full-suite verification + dep note
- [ ] Add `segno` to the project deps in `pyproject.toml` (it's installed in the venv; record it) — small commit `build: add segno for QR pairing`.
- [ ] Run `~/.skenv/bin/python -m pytest -q -p no:cacheprovider` — all 109 prior + the new pairing tests green.
