"""Regenerating one benchmark must not erase independent evidence sections."""

import json

from eval import benchmark
from watchtower.detect import features


def test_hdfs_generator_preserves_other_measured_sections(tmp_path, monkeypatch):
    result = json.loads(benchmark.OUT_JSON.read_text())
    result["model_version"] = 999
    output = tmp_path / "METRICS.md"
    output.write_text(
        "# Measured results\n\n"
        "## Independently labeled auth-log replay\n\nAIT evidence stays.\n\n"
        "## OpenSSH live rule replay\n\nOpenSSH evidence stays.\n\n"
        "## Time-disjoint HDFS validation\n\nTemporal evidence stays.\n\n"
        "## HDFS benchmark\n\nOld HDFS data.\n"
    )
    monkeypatch.setattr(benchmark, "OUT_MD", output)
    monkeypatch.setattr(benchmark, "OUT_JSON", tmp_path / "metrics.json")

    benchmark.write_markdown(result, [], dataset=features.FULL)

    document = output.read_text()
    assert document.count("# Measured results") == 1
    assert "AIT evidence stays." in document
    assert "OpenSSH evidence stays." in document
    assert "Temporal evidence stays." in document
    assert "Old HDFS data." not in document
    assert "version 999" in document
