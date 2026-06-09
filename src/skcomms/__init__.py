"""skcomms — sovereign communications for AI agents.

Multi-channel transport (Syncthing/file/websocket/WebRTC/Nostr/Tailscale/...)
unified under FQID ``<agent>@<operator>.<realm>`` sovereign addressing.

Transport layer (from skcomm, now canonical here):
    from skcomms import SKComm
    from skcomms.core import SKComm
    from skcomms.models import MessageEnvelope

FQID / realm layer (pre-alpha stubs, implementations landing in coord tasks):
    from skcomms.envelope import ...
    from skcomms.realm import ...
    from skcomms.identity import ...
    from skcomms.cluster import ...
"""

__version__ = "0.1.3"

from .core import SKComm
from .crypto import EnvelopeCrypto, KeyStore
from .models import (
    MessageEnvelope,
    MessageMetadata,
    MessagePayload,
    MessageType,
    RoutingConfig,
    RoutingMode,
)
from .signing import EnvelopeSigner, EnvelopeVerifier, SignedEnvelope, VerificationResult
from .transport import HealthStatus, SendResult, Transport, TransportError, TransportStatus

__all__ = [
    # Transport layer
    "SKComm",
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
    "SignedEnvelope",
    "EnvelopeSigner",
    "EnvelopeVerifier",
    "VerificationResult",
    # FQID / realm layer (stubs — implementations pending)
    # envelope, realm, identity, cluster importable directly
]
