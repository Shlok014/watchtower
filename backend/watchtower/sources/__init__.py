"""Log sources. Every one of them emits through pipeline.consumer.process_log."""

from .base import Source, ThreadedSource

__all__ = ["Source", "ThreadedSource"]
