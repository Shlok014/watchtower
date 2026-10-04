"""Score live HDFS lines with the trained model, one block at a time.

The model is a *block* classifier. It was fit on one vector per HDFS block id,
counting how many times each mined template appeared over that block's whole
lifetime — and a benchmark hands it completed blocks. A live stream does not.
That gap is the entire reason this module has a docstring instead of being three
lines inside the replay source.

**What is claimed here, precisely:** a block's counts are accumulated as its
lines arrive, and the model is asked for a probability against the partial
vector. The published F1 does *not* transfer to that number. It was measured on
complete blocks, and scoring a block that is one line old is a strictly harder
problem — the same model, different question. So this module reports a
probability, the number of lines behind it, and nothing else. No accuracy, no
confidence, no F1.

**Inference uses ``match()``, never ``parse()``.** ``parse`` mints a new
template for an unseen line and returns an id no column corresponds to. Lines
that match nothing are counted as ``unmatched`` and reported, because a rising
unmatched rate is the honest signal that the miner has drifted away from the
data — the thing that would otherwise silently hollow out every score.

Memory is bounded. HDFS_v1 has 575,061 blocks; holding a counter for each would
be a slow leak that looks like a working detector for the first hour.
"""

from collections import OrderedDict

import numpy as np

from . import model as model_mod
from .features import BLK, HEAD, file_sha256

DEFAULT_MAX_BLOCKS = 20_000
DEFAULT_RING = 200


class BlockScorer:
    """Accumulate per-block template counts and score them as they grow."""

    def __init__(
        self,
        bundle: model_mod.Bundle,
        parser,
        max_blocks: int = DEFAULT_MAX_BLOCKS,
        ring_size: int = DEFAULT_RING,
    ):
        self.bundle = bundle
        self.parser = parser
        self.max_blocks = max_blocks
        self.column = {tid: i for i, tid in enumerate(bundle.template_ids)}
        self._blocks: OrderedDict[str, np.ndarray] = OrderedDict()
        self._lines: OrderedDict[str, int] = OrderedDict()
        self.recent: list[dict] = []
        self.ring_size = ring_size
        self.lines_seen = 0
        self.unmatched = 0
        self.out_of_vocabulary = 0
        self.evicted = 0

    # ── observation ──────────────────────────────────────────────────────────
    def observe(self, message: str) -> list[dict]:
        """Feed one log line. Returns a verdict per block the line touches."""
        self.lines_seen += 1
        m = HEAD.match(message)
        content = m.group(1) if m else message.strip()
        blocks = set(BLK.findall(content))
        if not blocks:
            return []

        cid, _ = self.parser.match(content)
        if cid is None:
            # No existing template matched. Counted, and the block still gets a
            # verdict from what it already has — dropping the line silently
            # would make a drifting miner look like a quiet system.
            self.unmatched += 1
            col = None
        else:
            col = self.column.get(cid)
            if col is None:
                # Matched a template the model was never fit on. Distinct from
                # "matched nothing", and worth distinguishing: this one means
                # the miner and the model have diverged.
                self.out_of_vocabulary += 1

        verdicts = []
        for block in blocks:
            vec = self._blocks.get(block)
            if vec is None:
                vec = np.zeros(self.bundle.n_features, dtype=np.float32)
                self._blocks[block] = vec
                self._lines[block] = 0
            if col is not None:
                vec[col] += 1
            self._lines[block] += 1
            self._blocks.move_to_end(block)
            self._lines.move_to_end(block)
            verdicts.append(self._score(block, vec))

        self._evict()
        for v in verdicts:
            self.recent.append(v)
        if len(self.recent) > self.ring_size:
            del self.recent[: len(self.recent) - self.ring_size]
        return verdicts

    def _score(self, block: str, vec: np.ndarray) -> dict:
        proba = float(self.bundle.estimator.predict_proba(vec.reshape(1, -1))[0, 1])
        return {
            "block": block,
            "probability": round(proba, 4),
            "lines": self._lines[block],
            "model_version": self.bundle.version,
            # Said on every single verdict, not once in a footnote. This number
            # is not the benchmarked one and must never be read as if it were.
            "basis": "partial block — the published F1 was measured on complete blocks",
        }

    def _evict(self) -> None:
        while len(self._blocks) > self.max_blocks:
            block, _ = self._blocks.popitem(last=False)
            self._lines.pop(block, None)
            self.evicted += 1

    # ── reporting ────────────────────────────────────────────────────────────
    def probability_spread(self) -> dict | None:
        """min/median/max over the recent ring.

        Reported rather than described. Partial-block scores observed on this
        machine sit close to 1.0, and the likely reason is that the model is
        fitted with ``class_weight="balanced"`` against a 2.9% positive rate, so
        a sparse vector leans positive. That explanation is a hypothesis; the
        three numbers below are a measurement, and a reader can see the skew
        without being asked to take anyone's word for it.
        """
        if not self.recent:
            return None
        probs = sorted(v["probability"] for v in self.recent)
        mid = len(probs) // 2
        median = probs[mid] if len(probs) % 2 else (probs[mid - 1] + probs[mid]) / 2
        return {
            "samples": len(probs),
            "min": round(probs[0], 4),
            "median": round(median, 4),
            "max": round(probs[-1], 4),
        }

    def stats(self) -> dict:
        return {
            "model_version": self.bundle.version,
            "n_features": self.bundle.n_features,
            "lines_seen": self.lines_seen,
            "blocks_tracked": len(self._blocks),
            "blocks_evicted": self.evicted,
            "unmatched_lines": self.unmatched,
            "out_of_vocabulary_lines": self.out_of_vocabulary,
            "max_blocks": self.max_blocks,
            "held_out_metrics": self.bundle.metrics,
            "recent_probabilities": self.probability_spread(),
            "note": (
                "Live scores are over partial blocks and are not comparable to "
                "held_out_metrics, which were measured on complete blocks."
            ),
        }


# ─── process-wide scorer ─────────────────────────────────────────────────────
_scorer: BlockScorer | None = None
_load_error: str | None = None


def get() -> BlockScorer | None:
    return _scorer


def load_error() -> str | None:
    return _load_error


def enable(max_blocks: int = DEFAULT_MAX_BLOCKS) -> BlockScorer | None:
    """Load the newest model and start scoring. Returns None if there is none."""
    global _scorer, _load_error
    from .parser import LogParser, state_path

    try:
        bundle = model_mod.load_latest()
    except model_mod.ModelUnavailable as exc:
        _load_error = str(exc)
        _scorer = None
        return None
    dataset = bundle.meta.get("dataset", {})
    expected = dataset.get("miner_sha256")
    miner_stream = dataset.get("miner_stream")
    parser_state = state_path(miner_stream) if miner_stream else None
    if not expected or parser_state is None or not parser_state.is_file():
        _load_error = "model has no verified miner state; retrain before live scoring"
        _scorer = None
        return None
    if file_sha256(parser_state) != expected:
        _load_error = "model and miner state do not match; retrain before live scoring"
        _scorer = None
        return None
    # The same miner state the model's columns were mined from. A fresh miner
    # would match nothing and every score would be the model's answer to an
    # all-zero vector — a constant, delivered with a straight face.
    parser = LogParser(stream=miner_stream, persist=True)
    _scorer = BlockScorer(bundle, parser, max_blocks=max_blocks)
    _load_error = None
    return _scorer


def disable() -> None:
    global _scorer
    _scorer = None
