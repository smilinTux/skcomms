"""skcomms — sovereign communications for AI agents.

Multi-channel transport (Syncthing/file/websocket/WebRTC/Nostr/Tailscale/...)
unified under FQID ``<agent>@<operator>.<realm>`` sovereign addressing.

Transport layer (from skcomms, now canonical here):
    from skcomms import SKComms
    from skcomms.core import SKComms
    from skcomms.models import MessageEnvelope

FQID / realm layer (pre-alpha stubs, implementations landing in coord tasks):
    from skcomms.envelope import ...
    from skcomms.realm import ...
    from skcomms.identity import ...
    from skcomms.cluster import ...
"""

__version__ = "0.1.7"

from .core import SKComms, SKComm
from .crypto import EnvelopeCrypto, KeyStore
from .models import (
    MessageEnvelope,
    MessageMetadata,
    MessagePayload,
    MessageType,
    RoutingConfig,
    RoutingMode,
)
from .envelope import Envelope, SignedEnvelope
from .signing import EnvelopeSigner, EnvelopeVerifier, VerificationResult
from .transport import HealthStatus, SendResult, Transport, TransportError, TransportStatus

__all__ = [
    # Transport layer
    "SKComms",
    "SKComm",  # deprecated alias
    "MessageEnvelope",
    "MessageMetadata",
    "MessagePayload",
    "MessageType",
    "RoutingConfig",
    "RoutingMode",
    "Transport",
    "TransportError",
    "TransportStatus",
    "HealthStatus",
    "SendResult",
    "EnvelopeCrypto",
    "KeyStore",
    "Envelope",
    "SignedEnvelope",
    "EnvelopeSigner",
    "EnvelopeVerifier",
    "VerificationResult",
    # FQID / realm layer (stubs — implementations pending)
    # envelope, realm, identity, cluster importable directly
]
