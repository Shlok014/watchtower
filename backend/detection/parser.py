"""Log template mining with Drain3.

Drain groups raw log lines into templates by replacing the variable parts with
wildcards, so ``Receiving block blk_-1608999687919862906 src: /10.251.31.5:55504``
and the million lines like it collapse to one template. Everything downstream —
the feature vectors, the model — is built on those template ids.

Masking is the whole game. Without a mask for HDFS block ids, every distinct
``blk_-...`` spawns its own template and the template count explodes into the
hundreds of thousands, which is measurable immediately against the ground-truth
templates loghub ships (see eval/parsing.py).

Two miner instances are kept, ``hdfs`` and ``live``, with separate persisted
state. Their template id spaces are independent, and a model trained on one must
never be handed ids from the other.
"""

from pathlib import Path

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

STATE_DIR = Path(__file__).resolve().parent.parent / "data" / "drain"

# Order matters: the first pattern that matches a span wins.
MASKS = [
    # HDFS block identifiers — the single most important mask for this dataset.
    (r"blk_-?\d+", "BLK"),
    (r"(\d+\.){3}\d+(:\d+)?", "IP"),
    (r"/[-\w./]+", "PATH"),
    (r"0x[0-9a-fA-F]+", "HEX"),
    (r"\b\d+\b", "NUM"),
]


def build_config() -> TemplateMinerConfig:
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.4
    cfg.drain_depth = 4
    cfg.drain_max_children = 100
    cfg.drain_max_clusters = None
    cfg.masking_instructions = []
    from drain3.masking import MaskingInstruction

    for pattern, mask in MASKS:
        cfg.masking_instructions.append(MaskingInstruction(pattern, mask))
    return cfg


class LogParser:
    """Thin wrapper around drain3.TemplateMiner with per-stream persistence."""

    def __init__(self, stream: str = "live", persist: bool = True):
        self.stream = stream
        cfg = build_config()
        if persist:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            store = FilePersistence(str(STATE_DIR / f"drain3_{stream}.bin"))
            self.miner = TemplateMiner(store, config=cfg)
        else:
            self.miner = TemplateMiner(config=cfg)

    def parse(self, message: str):
        """Return (cluster_id, template) for one log line."""
        result = self.miner.add_log_message(message)
        return result["cluster_id"], result["template_mined"]

    def match(self, message: str):
        """Classify against existing templates without creating new ones.

        Used at scoring time: inventing a template for an unseen line at
        inference would give it an id the model has never been trained on.
        """
        cluster = self.miner.match(message)
        return (cluster.cluster_id, cluster.get_template()) if cluster else (None, None)

    @property
    def template_count(self) -> int:
        return len(self.miner.drain.clusters)

    def templates(self) -> dict:
        return {c.cluster_id: c.get_template() for c in self.miner.drain.clusters}
