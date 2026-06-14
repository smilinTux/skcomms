"""TTS audio stream track for WebRTC avatar streaming.

Produces av.AudioFrame objects from TTS-generated PCM audio at a steady
20ms cadence (Opus frame size). Audio is received via an asyncio.Queue
from the TTS pipeline and resampled to 48kHz (Opus native rate) if needed.

When no audio is available, silence frames are yielded to keep the RTP
stream alive and maintain timing.

Usage:
    audio_queue = asyncio.Queue(maxsize=50)
    track = TTSAudioTrack(audio_queue, input_sample_rate=24000)
    pc.addTrack(track)

    # Feed audio from TTS:
    await audio_queue.put(pcm_bytes)  # 16-bit signed, mono

Dependencies (optional extra):
    pip install 'skcomms[webrtc]'  →  aiortc>=1.9.0, av
"""

from __future__ import annotations

import asyncio
import fractions
import logging
import time
from typing import Optional

import numpy as np

logger = logging.getLogger("skcomms.transports.audio_track")

# Opus operates at 48kHz natively
OUTPUT_SAMPLE_RATE = 48000

# Standard Opus frame duration: 20ms
FRAME_DURATION_MS = 20

# Samples per Opus frame at 48kHz
SAMPLES_PER_FRAME = OUTPUT_SAMPLE_RATE * FRAME_DURATION_MS // 1000  # 960

# Audio clock rate for RTP (standard)
AUDIO_CLOCK_RATE = OUTPUT_SAMPLE_RATE  # 48000


class TTSAudioTrack:
    """aiortc AudioStreamTrack that yields TTS-generated audio.

    Receives raw PCM audio from the TTS pipeline via an asyncio.Queue,
    resamples to 48kHz if needed, and yields 20ms av.AudioFrame objects
    at a steady cadence.

    The track maintains an internal ring buffer to handle the mismatch
    between TTS chunk sizes (variable, often 100-500ms) and Opus frame
    sizes (fixed 20ms).

    Attributes:
        kind: Always ``"audio"`` (required by aiortc).
        input_sample_rate: Sample rate of incoming TTS audio.
    """

    kind = "audio"

    def __init__(
        self,
        audio_queue: asyncio.Queue,
        input_sample_rate: int = 24000,
        channels: int = 1,
    ):
        """Initialize the audio track.

        Args:
            audio_queue: asyncio.Queue of raw PCM bytes (16-bit signed, mono)
                from the TTS pipeline. Chunks can be any size.
            input_sample_rate: Sample rate of the incoming PCM audio.
                Common values: 16000 (Piper), 22050 (Piper), 24000 (Chatterbox),
                44100, 48000. Will be resampled to 48kHz for Opus.
            channels: Number of audio channels (1 = mono, 2 = stereo).
                TTS output is always mono; stereo is supported for future use.
        """
        from aiortc import MediaStreamTrack

        # Initialize the base class
        self.__class__ = type(
            "TTSAudioTrack",
            (MediaStreamTrack,),
            dict(self.__class__.__dict__),
        )
        MediaStreamTrack.__init__(self)
        self.kind = "audio"

        self._queue = audio_queue
        self.input_sample_rate = input_sample_rate
        self._channels = channels

        # Internal PCM buffer (48kHz, 16-bit samples as int16 numpy array)
        self._buffer = np.array([], dtype=np.int16)

        # Frame timing
        self._start_time: Optional[float] = None
        self._frame_count = 0
        self._time_base = fractions.Fraction(1, AUDIO_CLOCK_RATE)

        # Silence frame (pre-computed)
        self._silence = np.zeros(SAMPLES_PER_FRAME, dtype=np.int16)

        # State tracking
        self._speaking = False
        self._silence_after_speech_frames = 0
        # Yield 500ms of silence after speech ends to avoid abrupt cutoff
        self._silence_tail_frames = 25  # 25 * 20ms = 500ms

        logger.info(
            "TTSAudioTrack initialized: input=%dHz, output=%dHz, %dch",
            input_sample_rate,
            OUTPUT_SAMPLE_RATE,
            channels,
        )

    async def recv(self):
        """Yield the next 20ms audio frame.

        Called by aiortc's media pipeline in a loop. Maintains steady
        20ms pacing. Returns TTS audio when available, silence otherwise.

        Returns:
            av.AudioFrame (s16, 48kHz, mono) with correct PTS and time_base.
        """
        import av

        # Initialize timing on first call
        if self._start_time is None:
            self._start_time = time.monotonic()

        # Pace to 20ms intervals
        expected_time = self._start_time + (self._frame_count * FRAME_DURATION_MS / 1000.0)
        now = time.monotonic()
        if now < expected_time:
            await asyncio.sleep(expected_time - now)

        # Drain any new audio from the TTS queue into our buffer
        await self._drain_queue()

        # Extract one frame's worth of samples
        if len(self._buffer) >= SAMPLES_PER_FRAME:
            samples = self._buffer[:SAMPLES_PER_FRAME]
            self._buffer = self._buffer[SAMPLES_PER_FRAME:]
            self._speaking = True
            self._silence_after_speech_frames = 0
        else:
            # No audio available — yield silence
            samples = self._silence
            if self._speaking:
                self._silence_after_speech_frames += 1
                if self._silence_after_speech_frames >= self._silence_tail_frames:
                    self._speaking = False

        # Build av.AudioFrame
        frame = av.AudioFrame(
            format="s16",
            layout="mono" if self._channels == 1 else "stereo",
            samples=SAMPLES_PER_FRAME,
        )
        # Copy samples into the frame's plane buffer
        frame.planes[0].update(samples.tobytes())
        frame.sample_rate = OUTPUT_SAMPLE_RATE
        frame.pts = self._frame_count * SAMPLES_PER_FRAME
        frame.time_base = self._time_base

        self._frame_count += 1
        return frame

    async def _drain_queue(self) -> None:
        """Drain all available audio chunks from the TTS queue into the
        internal buffer, resampling to 48kHz as needed."""
        chunks_received = 0
        try:
            while True:
                pcm_bytes = self._queue.get_nowait()
                resampled = self._resample(pcm_bytes)
                self._buffer = np.concatenate([self._buffer, resampled])
                chunks_received += 1
        except asyncio.QueueEmpty:
            pass

        if chunks_received > 0:
            logger.debug(
                "Drained %d TTS chunks, buffer now %d samples (%.1f ms)",
                chunks_received,
                len(self._buffer),
                len(self._buffer) / OUTPUT_SAMPLE_RATE * 1000,
            )

    def _resample(self, pcm_bytes: bytes) -> np.ndarray:
        """Resample 16-bit PCM from input_sample_rate to 48kHz.

        Uses linear interpolation for simplicity. For production quality,
        consider using scipy.signal.resample_poly or soxr.

        Args:
            pcm_bytes: Raw 16-bit signed PCM audio bytes (mono).

        Returns:
            int16 numpy array resampled to 48kHz.
        """
        # Parse 16-bit signed PCM
        n_samples = len(pcm_bytes) // 2
        if n_samples == 0:
            return np.array([], dtype=np.int16)

        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32)

        if self.input_sample_rate == OUTPUT_SAMPLE_RATE:
            return samples.astype(np.int16)

        # Linear interpolation resampling
        ratio = OUTPUT_SAMPLE_RATE / self.input_sample_rate
        target_len = int(len(samples) * ratio)
        indices = np.linspace(0, len(samples) - 1, target_len)
        resampled = np.interp(indices, np.arange(len(samples)), samples)

        return np.clip(resampled, -32768, 32767).astype(np.int16)

    def flush(self) -> None:
        """Discard all buffered audio. Call when interrupting speech."""
        self._buffer = np.array([], dtype=np.int16)
        self._speaking = False
        self._silence_after_speech_frames = 0
        logger.debug("Audio buffer flushed")

    @property
    def buffered_ms(self) -> float:
        """Milliseconds of audio currently buffered."""
        return len(self._buffer) / OUTPUT_SAMPLE_RATE * 1000

    @property
    def is_speaking(self) -> bool:
        """True if the track is currently playing TTS audio."""
        return self._speaking
