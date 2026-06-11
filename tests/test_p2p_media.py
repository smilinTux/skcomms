"""P2PSession media: a direct P2P link carrying data channel AND an audio track.

Proves "both together" (sub-project B) — the offerer attaches an audio track, the
negotiated SDP carries an audio m-line, and the answerer's on_track fires. Uses a
minimal silent audio track so real SRTP media flows over aiortc loopback.
"""
import asyncio
import fractions

import av
import pytest
from aiortc import MediaStreamTrack

from skcomms.transports.p2p_session import P2PSession


class SilenceAudioTrack(MediaStreamTrack):
    """Minimal audio source: 20ms silent Opus-able frames at 48kHz mono."""

    kind = "audio"

    def __init__(self) -> None:
        super().__init__()
        self._pts = 0
        self._sr = 48000
        self._samples = 960  # 20ms @ 48kHz

    async def recv(self) -> av.AudioFrame:
        await asyncio.sleep(0.02)
        frame = av.AudioFrame(format="s16", layout="mono", samples=self._samples)
        for plane in frame.planes:
            plane.update(bytes(self._samples * 2))  # silence
        frame.pts = self._pts
        frame.sample_rate = self._sr
        frame.time_base = fractions.Fraction(1, self._sr)
        self._pts += self._samples
        return frame


@pytest.mark.asyncio
async def test_p2p_data_plus_audio():
    sessions: dict[str, P2PSession] = {}

    def make_send(target: str):
        async def _send(kind: str, payload: dict) -> None:
            await sessions[target].handle_signal(kind, payload)
        return _send

    got_track = asyncio.Event()
    a = P2PSession(send_signal=None)
    b = P2PSession(send_signal=None, on_track=lambda t: got_track.set())
    sessions["a"], sessions["b"] = a, b
    a._send_signal = make_send("b")
    b._send_signal = make_send("a")

    a.add_track(SilenceAudioTrack())

    try:
        await a.call()
        # the offer SDP must advertise audio (deterministic)
        assert "m=audio" in a.pc.localDescription.sdp
        # data channel still opens (both together)
        await a.wait_open(timeout=20)
        await b.wait_open(timeout=20)
        # and the audio track is received by the answerer (media actually flows)
        await asyncio.wait_for(got_track.wait(), timeout=20)
        assert b.received_tracks and b.received_tracks[0].kind == "audio"
    finally:
        await a.close()
        await b.close()
