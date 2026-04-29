"""Pytest smoke: mock-gate CPU path completes."""
from __future__ import annotations

import os
import runpy
import sys


def test_validate_locally_cpu_script():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root)
    sys.path.insert(0, root)
    env = os.environ.copy()
    env["PYTHONPATH"] = root
    env.setdefault("DARKSPACE_MOCK_GATE", "1")
    env.setdefault("DARKSPACE_READY_FOR_RUNPOD", "true")
    # runpy avoids subprocess import side effects
    runpy.run_path(
        os.path.join(root, "scripts", "validate_locally_cpu.py"),
        run_name="__main__",
    )
