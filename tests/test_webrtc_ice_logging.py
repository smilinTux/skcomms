"""Unit tests for WebRTC ICE-candidate debug logging (coord task 70253cd8).

These tests exercise the *logging-only* additions to the WebRTC transport:
the pure ICE-candidate SDP parser, the SDP candidate iterator, and the
``_log_ice_candidates`` helper. They require no aiortc/network (the parser
is pure Python and the transport lazy-imports aiortc), so they run in CI.

Security assertion: session credentials (ufrag/pwd) must NEVER appear in
any emitted log record.
"""

import logging

from skcomms.transports.webrtc import (
    WebRTCTransport,
    iter_sdp_candidate_summaries,
    summarize_ice_candidate,
)

# A representative candidate line carrying a ufrag credential we must not log.
SRFLX = (
    "candidate:842163049 1 udp 1677729535 203.0.113.7 55234 typ srflx "
    "raddr 10.0.0.5 rport 55234 generation 0 ufrag TOPSECRETUFRAG network-id 1"
)
HOST = "candidate:1 1 tcp 2122260223 192.168.0.41 9 typ host tcptype active"
RELAY = "candidate:9 1 udp 41885439 198.51.100.9 3478 typ relay raddr 0.0.0.0 rport 0"

SAMPLE_SDP = f"""v=0
o=- 0 0 IN IP4 0.0.0.0
a=group:BUNDLE 0
m=application 55234 UDP/DTLS/SCTP webrtc-datachannel
a=ice-ufrag:SHOULDNOTLOG
a=ice-pwd:ALSOSHOULDNOTLOG
a={SRFLX}
a={HOST}
a=end-of-candidates
"""


def test_summarize_srflx_extracts_only_safe_fields():
    s = summarize_ice_candidate(SRFLX)
    assert s == {
        "type": "srflx",
        "protocol": "udp",
        "address": "203.0.113.7",
        "port": "55234",
        "component": "1",
    }
    # The ufrag credential must never survive parsing.
    assert "TOPSECRETUFRAG" not in str(s)


def test_summarize_handles_prefix_and_missing_prefix():
    assert summarize_ice_candidate(HOST)["type"] == "host"
    assert summarize_ice_candidate(HOST[len("candidate:"):])["type"] == "host"


def test_summarize_relay_and_protocol_lowercased():
    s = summarize_ice_candidate(RELAY)
    assert s["type"] == "relay"
    assert s["protocol"] == "udp"
    assert s["address"] == "198.51.100.9"


def test_summarize_rejects_malformed():
    assert summarize_ice_candidate("") is None
    assert summarize_ice_candidate("not a candidate") is None
    assert summarize_ice_candidate("candidate:1 1 udp 100 1.2.3.4 5 nottyp host") is None


def test_iter_sdp_candidate_summaries():
    out = list(iter_sdp_candidate_summaries(SAMPLE_SDP))
    types = {c["type"] for c in out}
    assert types == {"srflx", "host"}
    assert len(out) == 2


def test_log_ice_candidates_emits_debug_and_info(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger="skcomms.transports.webrtc"):
        t._log_ice_candidates(SAMPLE_SDP, peer_id="ABCDEF0123456789", direction="local")

    debug_recs = [r for r in caplog.records if r.levelno == logging.DEBUG]
    info_recs = [r for r in caplog.records if r.levelno == logging.INFO]
    # One DEBUG line per candidate + one INFO summary line.
    assert len(debug_recs) == 2
    assert len(info_recs) == 1
    summary = info_recs[0].getMessage()
    assert "2 local ICE candidate(s)" in summary
    assert "srflx" in summary and "host" in summary
    # Peer id is truncated to 8 chars for privacy.
    assert "ABCDEF01" in summary


def test_log_ice_candidates_never_leaks_credentials(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger="skcomms.transports.webrtc"):
        t._log_ice_candidates(SAMPLE_SDP, peer_id="ABCDEF0123456789", direction="remote")
    blob = "\n".join(r.getMessage() for r in caplog.records)
    for secret in ("TOPSECRETUFRAG", "SHOULDNOTLOG", "ALSOSHOULDNOTLOG", "ice-pwd"):
        assert secret not in blob


def test_log_ice_candidates_empty_sdp_is_silent(caplog):
    t = WebRTCTransport(agent_fingerprint="DEADBEEFCAFE1234")
    with caplog.at_level(logging.DEBUG, logger="skcomms.transports.webrtc"):
        t._log_ice_candidates("", peer_id="ABCDEF0123456789", direction="local")
    assert caplog.records == []
