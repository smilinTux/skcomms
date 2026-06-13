"""Macro lexicon (spec §1c) — the VALIDATED token-efficiency layer.

A shared, versioned dictionary of terse phrases with explicit English definitions.
Agents carry render_prompt_block() in their system prompt so the receiving MODEL
expands macros semantically (-67% tokens, 100% fidelity when defined; bare jargon
without these definitions misreads ~1-in-5). NOT a wire codec — orthogonal to the
L0/L1/L2 byte codecs. The definitions are also the audit gloss (auditable by
construction).
"""

from __future__ import annotations

import hashlib
import json
import re

# Seed macros — the slot-typed forms the experiment validated to 100% fidelity.
# Each definition PINS the slot type, which is what kills the bare-jargon misreads
# (".41" host-not-version, "NA"/next-action-not-region, skmem-pg service-not-slab).
_SEED = {
    "GTD-sweep": "review all open coord tasks, reprioritize by the 4 C's, flag any "
                 "blocked, and propose next actions",
    "ROLLBACK <host> prev": "roll back the deployment ON HOST <host> to the previous "
                            "version (<host> is a machine, not a software version)",
    "NEXT-DO mine": "return the single highest-priority NEXT ACTION assigned to me "
                    "(not a region/geography)",
    "P0 <svc> down <host>": "priority-0 incident: service <svc> is down on host "
                            "<host>; page the operator, severity high",
    "ack+claim <id> eta<t>": "acknowledge and claim coord task <id> with an ETA of <t>",
    "mem-snapshot": "snapshot the agent's working MEMORY and run the daily digest "
                    "(agent memory, not OS RAM)",
    "secscan->PR": "run the security scanner, and if it finds issues open a fix PR",
    "CAB-gate <id>": "submit change <id> to the CAB for approval and wait for the vote",
    "hybrid-recall <q>": "run a hybrid (vector+BM25) memory recall for query <q>",
    "rebase-ship": "rebase onto the latest main, run tests, and if green push + open a PR",
}


class MacroLexicon:
    def __init__(self, macros: dict[str, str]) -> None:
        self._m = dict(macros)

    def expand(self, phrase: str) -> str | None:
        return self._m.get(phrase)

    def items(self):
        return self._m.items()

    @property
    def version(self) -> str:
        canonical = json.dumps(self._m, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:12]

    def render_prompt_block(self) -> str:
        lines = [_PROMPT_HEADER]
        for phrase, definition in self._m.items():
            lines.append(f"- `{phrase}` := {definition}")
        return "\n".join(lines)


_PROMPT_HEADER = (
    "SKGlossa macro lexicon — when a message uses one of these macros, expand it to "
    "EXACTLY the meaning below. If a message uses shorthand NOT listed here, do not "
    "guess — ask the sender to clarify.\n"
)


def expand_macros(text: str, lexicon: "MacroLexicon") -> str:
    """Literal substitution of known macros → definitions (for the audit gloss).

    SINGLE-PASS, non-re-entrant: one alternation regex of all phrases (longest
    first, so multi-word macros match before any prefix) with re.sub. Inserted
    definition text is never re-scanned, so a macro phrase appearing inside
    ANOTHER macro's definition is preserved (no latent double-expansion)."""
    phrases = sorted((p for p, _ in lexicon.items()), key=len, reverse=True)
    if not phrases:
        return text
    pattern = re.compile("|".join(re.escape(p) for p in phrases))
    return pattern.sub(lambda mt: f"({lexicon.expand(mt.group(0))})", text)


def default_macro_lexicon() -> MacroLexicon:
    return MacroLexicon(_SEED)
