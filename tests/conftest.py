import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REFERENCE_DIR = Path(__file__).parent / "reference"
DATA_DIR = Path(__file__).parent / "data"


def _node_ready() -> bool:
    """需要 node 以及参考实现依赖的 crypto-js"""
    if shutil.which("node") is None:
        return False
    probe = subprocess.run(
        ["node", "-e", "require('crypto-js');console.log('ok')"],
        cwd=REFERENCE_DIR, capture_output=True, text=True,
    )
    return probe.returncode == 0


NODE_READY = _node_ready()

requires_node = pytest.mark.skipif(
    not NODE_READY,
    reason="需要 node 与 crypto-js：cd tests/reference && npm install",
)


@pytest.fixture(scope="session")
def golden_numbers():
    with (DATA_DIR / "js_numbers.json").open(encoding="utf-8") as f:
        return json.load(f)
