"""Versioned semantic codebook (spec §3): concept/intent <-> short code.

Both peers must hold the same version to use the L2 codebook level; the version is
a stable hash of the mapping so agreement is verifiable in the handshake.
"""

from __future__ import annotations

import hashlib
import json

# Seed vocabulary — real SK intents agents actually exchange. Extend over time;
# changing this changes the version (peers must match to use L2).
_SEED = {
    "coord.claim": 1, "coord.complete": 2, "coord.create": 3, "coord.status": 4,
    "status.report": 5, "status.query": 6, "ack": 7, "nack": 8,
    "itil.incident": 9, "itil.change": 10, "gtd.capture": 11, "gtd.next": 12,
    "memory.store": 13, "memory.recall": 14, "presence.beacon": 15, "handoff": 16,
}


class Codebook:
    def __init__(self, mapping: dict[str, int]) -> None:
        self._c2n = dict(mapping)
        self._n2c = {n: c for c, n in mapping.items()}

    def code_for(self, concept: str) -> int | None:
        return self._c2n.get(concept)

    def concept_for(self, code: int) -> str | None:
        return self._n2c.get(code)

    @property
    def version(self) -> str:
        canonical = json.dumps(self._c2n, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def default_codebook() -> Codebook:
    return Codebook(_SEED)
