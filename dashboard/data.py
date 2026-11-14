"""Dashboard data layer (FR-U1): read the monitor's live state and alert log,
and send expire-session requests. Pure functions, no Streamlit, so it is unit
tested. The Streamlit app (app.py) is a thin view over this.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional


def latest_run(runs_dir: Path) -> Optional[Path]:
    runs = sorted(runs_dir.glob("*-monitor"))
    return runs[-1] if runs else None


def read_state(run_dir: Path) -> Dict:
    p = run_dir / "state.json"
    if not p.exists():
        return {"t": None, "sessions": [], "nd_counts": {}, "isolated": []}
    try:
        return json.loads(p.read_text())
    except (ValueError, OSError):
        return {"t": None, "sessions": [], "nd_counts": {}, "isolated": []}


def tail_jsonl(path: Path, limit: int = 100) -> List[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows[-limit:]


def read_alerts(run_dir: Path, limit: int = 100) -> List[dict]:
    return tail_jsonl(run_dir / "alerts.jsonl", limit)


def read_actions(run_dir: Path, limit: int = 100) -> List[dict]:
    return tail_jsonl(run_dir / "actions.jsonl", limit)


def request_expire(run_dir: Path, tenant: str, label: str) -> None:
    """Append an expire-session request the monitor will act on next tick."""
    with open(run_dir / "control.jsonl", "a") as fh:
        fh.write(json.dumps({"expire": {"tenant": tenant, "label": label}}) + "\n")
