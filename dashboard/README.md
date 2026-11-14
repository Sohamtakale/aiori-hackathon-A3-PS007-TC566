# dashboard/

Streamlit dashboard (FR-U1): live sessions, the **current** address mapping
only, alerts, isolation actions, and an expire-session button.

```sh
sudo lab/run_monitor.sh --dashboard            # terminal 1: writes runs/<run>/state.json
.venv/bin/streamlit run dashboard/app.py       # terminal 2
```

Point it at the monitor's run directory in the sidebar, or set `MAYFLY_RUN`
(or `MAYFLY_RUNS` to the parent of `*-monitor` dirs).

- The monitor with `--dashboard` writes `state.json` each tick (overwritten, not
  a log) and reads `control.jsonl` for expire requests.
- `data.py` is the pure read/write layer (unit tested); `app.py` is the view.
- Only the current address per pseudonym is shown. Address history (FR-U3) is
  off by design. The mapping populates as the monitor **observes** ND from each
  address, so a silent device shows no address until it sends traffic.
- The **Expire** button appends to `control.jsonl`; the monitor ends the session
  and wipes its keys on the next tick (UC3).
