"""alwaysdata Python WSGI entrypoint for the shared, on-demand demo.

The free hosting plan serves WSGI apps but does not run a separate continuous
source service. This entrypoint forces the public safety boundary and keeps
SQLite outside the code checkout so a code update does not erase demo history.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

os.environ["WATCHTOWER_PUBLIC_DEMO"] = "1"
os.environ["WATCHTOWER_SOURCES"] = ""
os.environ.setdefault("WATCHTOWER_DATA_DIR", str(Path.home() / "watchtower-data"))

from watchtower import config  # noqa: E402
from watchtower.app import create_app  # noqa: E402

config.set_config(config.from_env())
application = create_app(start_sources=False)
