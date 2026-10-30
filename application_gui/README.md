# DNSHawk — PySide6 application GUI

This is a new GUI layer for the existing DNSHawk project. It is deliberately separate from `dnshawk/gui/` so the existing Tkinter interface and detection backend remain unchanged.

## Pages

- **Overview** — live query-rate plot, total/last-hour counters, suspicious-domain summary, query-type counts.
- **Suspicious Domains** — suspicious domain/window records detected in the last rolling hour, with source IP, query count, ML probability and triggered rules.
- **Rule-Based Detection** — the five existing rule checks with observed value, threshold, status and explanation. This is kept separate from XGBoost output.
- **Network Activity** — recent captured DNS queries with a text filter.

## Run from the project root

Keep this folder inside the root of the extracted DNSHawk project, beside the `dnshawk/` package and `model_training/` folder.

Install dependencies in the same Python environment used by DNSHawk:

```powershell
python -m pip install PySide6 scapy xgboost
```

TShark must also be installed and available on `PATH`. In PowerShell, verify with:

```powershell
tshark --version
tshark -D
```

Launch from the project root:

```powershell
python -m application_gui.main
```

Enter the interface number from `tshark -D` (the current default is `6` based on the project's existing VMnet8 setup), then click **Start monitoring**. Run the terminal elevated if Npcap/TShark requires capture privileges. Stop capture before closing the application.

## Important implementation notes

- The app reuses the existing TShark capture, parser, 60-second aggregation, feature engine, `RuleDetector`, and D1 `MLDetector`; it does not retrain or alter the D1 model.
- The D1 model is expected at `model_training/DNSHawk_D1_artifacts/models/xgboost_dns_tunnel_d1.json`.
- The minimum evidence rule (10 queries) and model probability threshold (0.5) come from the existing ML detector.
- Live captured records are shown only after capture begins. No demo data is fabricated.
- The last-hour view is filtered by detection timestamps. A domain/window may be updated while new events arrive in that same 60-second window.
- The source project's DNS parser currently assumes the last two labels are the domain. This GUI intentionally preserves that behavior rather than silently changing backend domain parsing.
- The current capture command filters `udp port 53`, matching the existing collector; TCP DNS is not added by this GUI.
- This is an initial integration GUI. Validate it against your actual TShark interface and lab traffic before using it for evaluation or presenting metrics as live detection performance.
