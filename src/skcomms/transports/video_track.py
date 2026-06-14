"""MuseTalk video stream track for WebRTC avatar streaming.

Produces av.VideoFrame objects from MuseTalk lip-sync output at a target
frame rate. Frames are fed via an asyncio.Queue from the MuseTalk inference
pipeline. When no frames are available, the last frame is repeated to
maintain smooth PTS progression.

Usage:
    frame_queue = asyncio.Queue(maxsize=3)
    track = MuseTalkVideoTrack(frame_queue, fps=20, width=1280, height=720)
    pc.addTrack(track)

    # Feed frames from MuseTalk:
    await frame_queue.put(bgr_numpy_array)

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

logger = logging.getLogger("skcomms.transports.video_track")

# RTP video clock rate (standard, do not change)
VIDEO_CLOCK_RATE = 90000

# Default target FPS for avatar streaming
DEFAULT_FPS = 20

# Default output resolution
DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 720


class MuseTalkVideoTrack:
    """aiortc VideoStreamTrack that yields MuseTalk lip-sync frames.

    Subclasses aiortc's MediaStreamTrack (video kind). Frames are received
    from the MuseTalk inference pipeline via an asyncio.Queue. The track
    handles frame pacing, format conversion, and idle frame repetition.

    Attributes:
        kind: Always ``"video"`` (required by aiortc).
        fps: Target frames per second.
        width: Output frame width in pixels.
        height: Output frame height in pixels.
    """

    kind = "video"

    def __init__(
        self,
        frame_queue: asyncio.Queue,
        fps: int = DEFAULT_FPS,
        width: int = DEFAULT_WIDTH,
        height: int = DEFAULT_HEIGHT,
        idle_frame: Optional[np.ndarray] = None,
    ):
        """Initialize the video track.

        Args:
            frame_queue: asyncio.Queue of BGR numpy arrays from MuseTalk.
                Queue maxsize should be small (2-3) to bound latency.
            fps: Target frame rate. MuseTalk should produce frames at this rate.
            width: Output frame width. Frames are resized if needed.
            height: Output frame height. Frames are resized if needed.
            idle_frame: Static portrait frame (BGR numpy) to use when no
                MuseTalk output is available. If None, a black frame is used.
        """
        # Import here to allow module to load without aiortc installed
        from aiortc import MediaStreamTrack

        # Initialize the base class
        self.__class__ = type(
            "MuseTalkVideoTrack",
            (MediaStreamTrack,),
            dict(self.__class__.__dict__),
        )
        MediaStreamTrack.__init__(self)
        self.kind = "video"

        self._queue = frame_queue
        self.fps = fps
        self.width = width
        self.height = height

        # Frame timing
        self._start_time: Optional[float] = None
        self._frame_count = 0
        self._time_base = fractions.Fraction(1, VIDEO_CLOCK_RATE)

        # Idle/fallback frame
        if idle_frame is not None:
            self._idle_frame = self._prepare_frame(idle_frame)
        else:
            self._idle_frame = self._make_black_frame()

        self._last_frame = self._idle_frame

        logger.info(
            "MuseTalkVideoTrack initialized: %dx%d @ %d FPS",
            width,
            height,
            fps,
        )

    async def recv(self):
        """Yield the next video frame with proper timing.

        Called by aiortc's media pipeline in a loop. Paces itself to the
        target FPS using wall-clock timing. Returns the latest MuseTalk
        frame, or repeats the last frame if no new frame is available.

        Returns:
            av.VideoFrame in yuv420p format with correct PTS and time_base.
        """

        # Initialize start time on first call
        if self._start_time is None:
            self._start_time = time.monotonic()

        # Compute target wall-clock time for this frame
        expected_time = self._start_time + (self._frame_count / self.fps)
        now = time.monotonic()

        # Sleep until it's time for this frame
        if now < expected_time:
            await asyncio.sleep(expected_time - now)

        # Try to get a new frame from MuseTalk (non-blocking)
        frame = await self._get_latest_frame()

        if frame is not None:
            self._last_frame = frame
        else:
            frame = self._last_frame

        # Set timing metadata
        frame.pts = self._frame_count * VIDEO_CLOCK_RATE // self.fps
        frame.time_base = self._time_base

        self._frame_count += 1
        return frame

    async def _get_latest_frame(self):
        """Get the latest frame from the queue, dropping stale ones.

        If multiple frames have accumulated (MuseTalk running faster than
        real-time), takes the newest and discards the rest to minimize
        latency.

        Returns:
            av.VideoFrame in yuv420p, or None if queue is empty.
        """
        latest = None
        try:
            while True:
                bgr_array = self._queue.get_nowait()
                latest = bgr_array
        except asyncio.QueueEmpty:
            pass

        if latest is not None:
            return self._prepare_frame(latest)
        return None

    def _prepare_frame(self, bgr_array: np.ndarray):
        """Convert a BGR numpy array to an av.VideoFrame in yuv420p.

        Handles resizing if the input doesn't match the target resolution.

        Args:
            bgr_array: BGR uint8 numpy array (H, W, 3) from MuseTalk/OpenCV.

        Returns:
            av.VideoFrame in yuv420p format.
        """
        import av
        import cv2

        # Resize if needed
        h, w = bgr_array.shape[:2]
        if w != self.width or h != self.height:
            bgr_array = cv2.resize(
                bgr_array,
                (self.width, self.height),
                interpolation=cv2.INTER_LINEAR,
            )

        # BGR → RGB (av.VideoFrame.from_ndarray expects RGB)
        rgb_array = cv2.cvtColor(bgr_array, cv2.COLOR_BGR2RGB)

        # Create av.VideoFrame from numpy array
        frame = av.VideoFrame.from_ndarray(rgb_array, format="rgb24")

        # Convert to yuv420p (required for WebRTC)
        frame = frame.reformat(format="yuv420p")

        return frame

    def _make_black_frame(self):
        """Create a black fallback frame.

        Returns:
            av.VideoFrame (yuv420p, black).
        """
        import av

        black = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        frame = av.VideoFrame.from_ndarray(black, format="rgb24")
        return frame.reformat(format="yuv420p")

    def set_idle_frame(self, portrait_bgr: np.ndarray) -> None:
        """Update the idle portrait frame shown when MuseTalk is not generating.

        Args:
            portrait_bgr: BGR numpy array of the agent's portrait.
        """
        self._idle_frame = self._prepare_frame(portrait_bgr)
        # Also update last_frame if we're currently showing idle
        if self._last_frame is self._idle_frame:
            self._last_frame = self._idle_frame

    def reset_timing(self) -> None:
        """Reset frame timing. Call when starting a new speech segment."""
        self._start_time = None
        self._frame_count = 0
