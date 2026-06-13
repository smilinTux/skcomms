"""FQID <-> Meshtastic node-id mapping (spec §5), persisted. Populated by pairing;
unmapped peers are reached by broadcast on the SK channel + Ed25519-verified."""

from __future__ import annotations

import json
from pathlib import Path

SK_CHANNEL = "skworld"
_DEFAULT_PATH = Path.home() / ".skcomm" / "lora-nodes.json"


class NodeMap:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else _DEFAULT_PATH
        self._f2n: dict[str, str] = {}
        self._n2f: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        self._f2n = dict(d.get("fqid_to_node", {}))
        self._n2f = {n: f for f, n in self._f2n.items()}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"fqid_to_node": self._f2n}, indent=2),
                             encoding="utf-8")

    def bind(self, fqid: str, node_id: str) -> None:
        # Clear any stale entries before rebinding so the forward/reverse maps
        # stay consistent: drop fqid's old node, and drop node_id's old fqid.
        old_node = self._f2n.get(fqid)
        if old_node is not None:
            self._n2f.pop(old_node, None)
        old_fqid = self._n2f.get(node_id)
        if old_fqid is not None:
            self._f2n.pop(old_fqid, None)
        self._f2n[fqid] = node_id
        self._n2f[node_id] = fqid
        self._save()

    def node_for(self, fqid: str) -> str | None:
        return self._f2n.get(fqid)

    def fqid_for(self, node_id: str) -> str | None:
        return self._n2f.get(node_id)
