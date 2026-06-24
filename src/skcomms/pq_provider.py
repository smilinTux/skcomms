"""Hybrid-KEM prekey provider for the envelope transport (PQC cut-over).

A small duck-typed object that :class:`skcomms.crypto.EnvelopeCrypto` consults to
negotiate hybrid X25519+ML-KEM-768 confidentiality BY DEFAULT:

* ``resolve_bundle(identity)`` — the recipient's published prekey bundle.
* ``own_private()`` — this agent's hybrid private key (to open inbound).
* ``short(identity)`` / ``own_short()`` — name normalisers for the downgrade AAD.

The bundles + agent keypair live in the shared ``~/.skchat/pqc/`` store written
by ``skchat.pq_prekeys`` (single wire format across skchat ↔ skcomms). This
provider reads that store directly so the transport layer can negotiate hybrid
without a hard skchat import; if liboqs / the store is unavailable, every method
returns ``None`` and confidentiality stays classical — honest, never raised.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("skcomms.pq_provider")

HYBRID_SUITE = "x25519-mlkem768"
CLASSICAL_SUITE = "x25519-pgp-wrap-v1"


def _pqc_dir() -> Path:
    home = Path(os.environ.get("SKCHAT_HOME", str(Path.home() / ".skchat")))
    return home / "pqc"


def _short(identity: str) -> str:
    s = identity[len("capauth:") :] if identity.startswith("capauth:") else identity
    return s.split("@")[0]


def _current_agent() -> str:
    return (
        os.environ.get("SKAGENT")
        or os.environ.get("SKCAPSTONE_AGENT")
        or os.environ.get("SKMEMORY_AGENT")
        or "lumina"
    ).split("@")[0]


class SharedStorePrekeyProvider:
    """Hybrid prekey provider backed by the ``~/.skchat/pqc/`` keystore."""

    def __init__(self, agent: Optional[str] = None) -> None:
        self._agent = (agent or _current_agent()).split("@")[0]

    # -- transport-facing protocol -----------------------------------------

    def short(self, identity: str) -> str:
        return _short(identity)

    def own_short(self) -> str:
        return self._agent

    def resolve_bundle(self, identity: str) -> Optional[dict]:
        """Return the recipient's published hybrid prekey bundle, or None."""
        short = _short(identity)
        # Our own identity → our own published bundle.
        if short == self._agent:
            pub = self.own_public()
            if pub is not None:
                return {
                    "suite": HYBRID_SUITE,
                    "hybrid_public_hex": pub.hex(),
                }
            return None
        path = _pqc_dir() / "peers" / f"{short}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except Exception:
            logger.debug("corrupt peer prekey for %s", short, exc_info=True)
            return None
        if data.get("suite") == HYBRID_SUITE and data.get("hybrid_public_hex"):
            return data
        return None

    # -- own keypair --------------------------------------------------------

    def _key_paths(self):
        d = _pqc_dir()
        return d / f"{self._agent}_hybrid.key", d / f"{self._agent}_hybrid.pub"

    def own_private(self) -> Optional[bytes]:
        priv_path, _ = self._key_paths()
        # Fall back to lumina's legacy filename if the agent file is absent.
        if not priv_path.exists() and self._agent == "lumina":
            priv_path = _pqc_dir() / "lumina_hybrid.key"
        if not priv_path.exists():
            return None
        try:
            return bytes.fromhex(priv_path.read_text().strip())
        except Exception:
            logger.debug("unreadable hybrid private key", exc_info=True)
            return None

    def own_public(self) -> Optional[bytes]:
        _, pub_path = self._key_paths()
        if not pub_path.exists() and self._agent == "lumina":
            pub_path = _pqc_dir() / "lumina_hybrid.pub"
        if not pub_path.exists():
            return None
        try:
            return bytes.fromhex(pub_path.read_text().strip())
        except Exception:
            return None


def default_provider(agent: Optional[str] = None) -> Optional["SharedStorePrekeyProvider"]:
    """Return a provider only if the hybrid backend is actually available.

    Returns ``None`` when liboqs is missing so the transport stays classical
    (the engine's ``hybrid_provider`` is then None → unchanged behaviour).
    """
    try:
        from . import pqkem

        if not pqkem.is_available():
            return None
    except Exception:
        return None
    return SharedStorePrekeyProvider(agent)
