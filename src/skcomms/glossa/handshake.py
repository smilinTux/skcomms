"""Capability handshake (spec §4): exchange descriptors -> densest mutually-
decodable level. Deterministic + symmetric so both peers compute the same Session.
Signing is the anti-spoof layer (reuses capauth); the level math is signing-free.
"""

from __future__ import annotations

from dataclasses import dataclass

from skcomms.glossa import codec


@dataclass
class CapabilityDescriptor:
    fqid: str
    model_tier: str          # "large" | "small" | ... — the weaker-peer signal
    max_level: int           # highest codec level this agent supports
    codebook_version: str    # the L2 codebook version this agent holds


@dataclass
class Session:
    level: int
    codebook_version: str


def negotiate(local: CapabilityDescriptor, remote: CapabilityDescriptor) -> Session:
    level = min(local.max_level, remote.max_level)
    # L2 (codebook) requires both to hold the SAME codebook version; else cap at L1.
    if level >= codec.L2_CODEBOOK and local.codebook_version != remote.codebook_version:
        level = codec.L1_SCHEMA
    return Session(level=level, codebook_version=local.codebook_version)
