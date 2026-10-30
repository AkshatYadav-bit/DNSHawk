# GUI integration map

`main.py` — Qt Widgets shell, navigation, tables, metric cards, filtering and visual styling.

`worker.py` — QThread-based capture and processing. It calls the existing DNSHawk collector/parser/features/rule detector/ML detector and emits compact snapshots to the GUI via Qt signals.

`charts.py` — lightweight QPainter charts; avoids requiring QtCharts or an additional plotting library.

The existing `dnshawk/` package and D1 model artifact are dependencies and are intentionally not copied or modified in this GUI-only deliverable.
