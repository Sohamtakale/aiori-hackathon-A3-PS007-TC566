#!/usr/bin/env python3
"""Mayfly dashboard (FR-U1): live sessions, the current address mapping only,
alerts, and an expire-session button.

  sudo lab/run_monitor.sh --dashboard          # terminal 1 (writes runs/<run>/state.json)
  .venv/bin/streamlit run dashboard/app.py     # terminal 2

Point it at the monitor's run directory with the MAYFLY_RUN env var or the
sidebar. It shows ONLY the current address for each pseudonym -- no history
(FR-U3 is off by default) and no raw addresses are persisted here.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dashboard.data import (latest_run, read_actions, read_alerts, read_state,  # noqa: E402
                            request_expire)

st.set_page_config(page_title="Mayfly monitor", page_icon="🦟", layout="wide")


def pick_run_dir() -> Path:
    default = os.environ.get("MAYFLY_RUN", "")
    runs_dir = Path(os.environ.get("MAYFLY_RUNS", "runs"))
    guess = latest_run(runs_dir) if not default else Path(default)
    val = st.sidebar.text_input("Monitor run directory", value=str(guess) if guess else "")
    return Path(val) if val else Path(".")


def main() -> None:
    st.title("🦟 Mayfly — IPv6 ND monitor")
    run_dir = pick_run_dir()
    st.sidebar.checkbox("Show address history (FR-U3)", value=False, disabled=True,
                        help="Disabled by design: the monitor keeps current mappings only.")
    st.sidebar.caption("Address history is off by design (FR-U3); only current mappings are shown.")
    auto = st.sidebar.checkbox("Auto-refresh (2s)", value=True)

    state = read_state(run_dir)
    if state["t"] is None:
        st.warning("No state.json in %s. Start the monitor with --dashboard." % run_dir)
    isolated = state.get("isolated", [])
    c1, c2, c3 = st.columns(3)
    c1.metric("Live sessions", len(state["sessions"]))
    c2.metric("Monitor clock", "%.0fs" % (state["t"] or 0))
    c3.metric("Isolated ports", len(isolated))
    if isolated:
        st.error("Isolated (L2): " + ", ".join(isolated))

    st.subheader("Live sessions — current address mapping")
    if state["sessions"]:
        for s in state["sessions"]:
            cols = st.columns([1, 2, 1, 3, 1, 2])
            cols[0].write("**%s**" % s["tenant"])
            cols[1].code(s["label"])
            cols[2].write("e%s" % s["epoch"])
            cols[3].code(s["address"] or "—")
            cols[4].write(("%ss ago" % s["last_seen"]) if s["last_seen"] is not None else "—")
            if cols[5].button("Expire", key="x/%s/%s" % (s["tenant"], s["label"])):
                request_expire(run_dir, s["tenant"], s["label"])
                st.toast("Expire requested for %s" % s["label"])
    else:
        st.info("No active sessions.")

    st.subheader("Alerts")
    alerts = read_alerts(run_dir, 50)
    if alerts:
        st.dataframe(list(reversed(alerts)), use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet.")

    actions = read_actions(run_dir, 50)
    if actions:
        st.subheader("Isolation actions")
        st.dataframe(list(reversed(actions)), use_container_width=True, hide_index=True)

    if auto:
        time.sleep(2)
        st.rerun()


main()
