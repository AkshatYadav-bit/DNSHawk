import sys
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QStackedWidget, QGridLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QComboBox,
    QAbstractItemView
)

from application_gui.worker import CaptureWorker
from application_gui.charts import LineChart, DonutPlaceholder


STYLE = """
* { font-family: 'Segoe UI'; font-size: 10pt; }
QMainWindow, QWidget#root { background: #0b1120; color: #e5e7eb; }
QFrame#sidebar { background: #080d18; border-right: 1px solid #202b3d; }
QLabel#brand { font-size: 18pt; font-weight: 800; color: #f8fafc; padding: 12px 8px; }
QLabel#muted { color: #94a3b8; }
QLabel#pageTitle { font-size: 20pt; font-weight: 700; color: #f8fafc; }
QLabel#metricValue { font-size: 23pt; font-weight: 700; color: #f8fafc; }
QFrame#panel, QFrame#metric { background: #111827; border: 1px solid #263247; border-radius: 10px; }
QPushButton { background: transparent; color: #aebbd0; border: 0; border-radius: 7px; padding: 11px 12px; text-align: left; }
QPushButton:hover { background: #172338; color: white; }
QPushButton[active="true"] { background: #12304a; color: #7dd3fc; font-weight: 700; }
QPushButton#primary { background: #0284c7; color: white; font-weight: 700; text-align: center; }
QPushButton#danger { background: #991b1b; color: white; font-weight: 700; text-align: center; }
QLineEdit, QComboBox { background: #0b1220; color: #e5e7eb; border: 1px solid #334155; border-radius: 6px; padding: 8px; }
QTableWidget { background: #0f172a; alternate-background-color: #111c30; gridline-color: #263247; border: 1px solid #263247; border-radius: 8px; }
QHeaderView::section { background: #1e293b; color: #cbd5e1; padding: 8px; border: 0; font-weight: 600; }
QTableWidget::item { padding: 5px; }
"""


def panel():
    f = QFrame()
    f.setObjectName("panel")
    return f


def make_table(headers):
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    t.verticalHeader().setVisible(False)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    return t


def put_rows(table, rows):
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            item = QTableWidgetItem(str(value if value is not None else "—"))
            item.setToolTip(str(value if value is not None else "—"))
            table.setItem(r, c, item)


class Metric(QFrame):
    def __init__(self, label, value="0", detail=""):
        super().__init__()
        self.setObjectName("metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        top = QLabel(label); top.setObjectName("muted")
        self.value = QLabel(value); self.value.setObjectName("metricValue")
        self.detail = QLabel(detail); self.detail.setObjectName("muted")
        layout.addWidget(top); layout.addWidget(self.value); layout.addWidget(self.detail)

    def set_value(self, value):
        self.value.setText(str(value))


class DNSHawkWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DNSHawk | DNS Tunneling Detection")
        self.resize(1500, 900)
        self.setMinimumSize(1100, 700)
        self.worker = None
        self.snapshot = {}
        self.nav_buttons = []
        root = QWidget(); root.setObjectName("root")
        outer = QHBoxLayout(root); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0)
        sidebar = QFrame(); sidebar.setObjectName("sidebar"); sidebar.setFixedWidth(218)
        side = QVBoxLayout(sidebar); side.setContentsMargins(14, 12, 14, 14)
        brand = QLabel("DNSHawk"); brand.setObjectName("brand")
        sub = QLabel("NETWORK DEFENSE"); sub.setObjectName("muted")
        side.addWidget(brand); side.addWidget(sub); side.addSpacing(24)
        self.pages = QStackedWidget()
        for title, icon in [("Overview", "◈"), ("Suspicious Domains", "⚠"), ("Rule-Based Detection", "≋"), ("Network Activity", "⌁")]:
            b = QPushButton(f"{icon}   {title}")
            b.setProperty("active", title == "Overview")
            b.clicked.connect(lambda checked=False, t=title: self.navigate(t))
            side.addWidget(b); self.nav_buttons.append((title, b))
        side.addStretch()
        side.addWidget(QLabel("CAPTURE INTERFACE"))
        self.interface = QLineEdit("6"); self.interface.setPlaceholderText("e.g. 6 or \\Device\\NPF_…")
        side.addWidget(self.interface)
        self.capture_status = QLabel("●  Not monitoring"); self.capture_status.setObjectName("muted")
        side.addWidget(self.capture_status)
        self.start_btn = QPushButton("▶   Start monitoring"); self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.start_capture); side.addWidget(self.start_btn)
        self.stop_btn = QPushButton("■   Stop monitoring"); self.stop_btn.setObjectName("danger")
        self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_capture); side.addWidget(self.stop_btn)
        outer.addWidget(sidebar)
        main = QWidget()
        self.main_layout = QVBoxLayout(main); self.main_layout.setContentsMargins(26, 22, 26, 22); self.main_layout.setSpacing(18)
        outer.addWidget(main, 1)
        self.setCentralWidget(root)
        self._build_pages()
        self.navigate("Overview")

    def _page_header(self, title, description):
        row = QHBoxLayout()
        col = QVBoxLayout()
        t = QLabel(title); t.setObjectName("pageTitle")
        d = QLabel(description); d.setObjectName("muted")
        col.addWidget(t); col.addWidget(d)
        row.addLayout(col); row.addStretch()
        return row

    def _build_pages(self):
        # Overview
        page = QWidget(); l = QVBoxLayout(page); l.setSpacing(16)
        l.addLayout(self._page_header("Overview", "Live DNS telemetry and detection summary"))
        metrics = QGridLayout(); metrics.setSpacing(12)
        self.m_total = Metric("Queries observed", "0", "Since monitoring started")
        self.m_hour = Metric("Queries · last hour", "0", "Rolling 60-minute view")
        self.m_suspicious = Metric("Suspicious domains", "0", "Detections in the last hour")
        self.m_alerts = Metric("Active alerts", "0", "Domain/window-level findings")
        for i, m in enumerate([self.m_total, self.m_hour, self.m_suspicious, self.m_alerts]): metrics.addWidget(m, 0, i)
        l.addLayout(metrics)
        chartrow = QHBoxLayout(); chartrow.setSpacing(14)
        self.rate_chart = LineChart()
        self.qtype_chart = DonutPlaceholder()
        chartrow.addWidget(self.rate_chart, 2); chartrow.addWidget(self.qtype_chart, 1)
        l.addLayout(chartrow)
        p = panel(); pl = QVBoxLayout(p); pl.addWidget(QLabel("Recently detected suspicious domains"))
        self.overview_table = make_table(["Domain", "Source IP", "Queries", "ML probability", "Triggered rules", "Detected at"])
        pl.addWidget(self.overview_table); l.addWidget(p, 1)
        self.pages.addWidget(page)

        # Suspicious domains
        page = QWidget(); l = QVBoxLayout(page); l.setSpacing(14)
        l.addLayout(self._page_header("Suspicious Domains", "Detection records from the rolling last-hour window"))
        self.domain_filter = QLineEdit(); self.domain_filter.setPlaceholderText("Filter by domain, source IP, or reason…")
        self.domain_filter.textChanged.connect(self.refresh_suspicious)
        l.addWidget(self.domain_filter)
        self.suspicious_table = make_table(["Detection time", "Domain", "Source IP", "Queries", "ML probability", "Rule triggers", "Reasons"])
        l.addWidget(self.suspicious_table, 1)
        self.pages.addWidget(page)

        # Rules
        page = QWidget(); l = QVBoxLayout(page); l.setSpacing(14)
        l.addLayout(self._page_header("Rule-Based Detection", "Existing five heuristic rules; displayed separately from XGBoost"))
        info = QLabel("A rule trigger is evidence, not by itself proof of DNS tunneling. Rule thresholds are read from dnshawk/config.py.")
        info.setObjectName("muted"); l.addWidget(info)
        self.rules_table = make_table(["Domain", "Source IP", "Queries", "Rule", "Observed", "Threshold", "Status", "Reason"])
        l.addWidget(self.rules_table, 1)
        self.pages.addWidget(page)

        # Network activity
        page = QWidget(); l = QVBoxLayout(page); l.setSpacing(14)
        l.addLayout(self._page_header("Network Activity", "Recent DNS query events from the selected capture interface"))
        self.event_filter = QLineEdit(); self.event_filter.setPlaceholderText("Search query, domain, source IP…")
        self.event_filter.textChanged.connect(self.refresh_events); l.addWidget(self.event_filter)
        self.events_table = make_table(["Time (UTC)", "Source IP", "Domain", "Query", "Type", "Query length"])
        l.addWidget(self.events_table, 1)
        self.pages.addWidget(page)

    def navigate(self, title):
        index = {"Overview": 0, "Suspicious Domains": 1, "Rule-Based Detection": 2, "Network Activity": 3}[title]
        self.pages.setCurrentIndex(index)
        for name, button in self.nav_buttons:
            button.setProperty("active", name == title)
            button.style().unpolish(button); button.style().polish(button)
        # Main layout was created before pages; add stack only once.
        if self.main_layout.indexOf(self.pages) < 0:
            self.main_layout.addWidget(self.pages, 1)

    def start_capture(self):
        if self.worker and self.worker.isRunning():
            return
        interface = self.interface.text().strip()
        if not interface:
            QMessageBox.warning(self, "Capture interface required", "Enter a TShark interface number or interface name.")
            return
        self.worker = CaptureWorker(interface=interface)
        self.worker.snapshot.connect(self.on_snapshot)
        self.worker.status.connect(self.on_status)
        self.worker.error.connect(self.on_error)
        self.worker.start()
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True); self.interface.setEnabled(False)
        self.on_status("Starting capture…")

    def stop_capture(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.on_status("Stopping…")

    def on_status(self, status):
        self.capture_status.setText(f"●  {status}")

    def on_error(self, message):
        QMessageBox.warning(self, "DNSHawk capture error", message + "\n\nCheck that TShark is installed, the interface is correct, and the app has capture permissions.")

    def on_snapshot(self, data):
        self.snapshot = data
        self.m_total.set_value(data.get("total_queries", 0))
        self.m_hour.set_value(data.get("queries_last_hour", 0))
        self.m_suspicious.set_value(data.get("suspicious_count", 0))
        self.m_alerts.set_value(data.get("alerts_count", 0))
        self.rate_chart.set_points(data.get("query_rate", []))
        self.qtype_chart.set_counts(data.get("qtype_counts", {}))
        self.refresh_suspicious(); self.refresh_rules(); self.refresh_events()
        status = data.get("status", "")
        if status in ("Stopped", "Capture error"):
            self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False); self.interface.setEnabled(True)

    def refresh_suspicious(self):
        data = self.snapshot.get("suspicious_domains", [])
        query = self.domain_filter.text().lower() if hasattr(self, "domain_filter") else ""
        data = [d for d in data if query in str(d).lower()]
        rows = []
        for d in data[:500]:
            prob = d.get("probability")
            rows.append((d.get("detection_time", "")[:19].replace("T", " "),
                         d.get("domain"), d.get("src_ip"), d.get("query_count"),
                         f"{prob:.1%}" if isinstance(prob, (int, float)) else "N/A",
                         ", ".join(d.get("triggered_rules", [])) or "—",
                         ", ".join(d.get("reasons", [])) or "—"))
        if hasattr(self, "suspicious_table"):
            put_rows(self.suspicious_table, rows)
            put_rows(self.overview_table, [r[1:] if False else (r[1], r[2], r[3], r[4], r[5], r[0]) for r in rows[:8]])

    def refresh_rules(self):
        if not hasattr(self, "rules_table"): return
        rows = []
        for d in self.snapshot.get("windows", []):
            for name, result in d.get("rules", {}).items():
                rows.append((d.get("domain"), d.get("src_ip"), d.get("query_count"), name,
                             f'{result.get("value", 0):.3f}', f'{result.get("threshold", 0):.3f}',
                             "TRIGGERED" if result.get("triggered") else "Clear",
                             result.get("reason", "")))
        put_rows(self.rules_table, rows[:1500])

    def refresh_events(self):
        if not hasattr(self, "events_table"): return
        q = self.event_filter.text().lower() if hasattr(self, "event_filter") else ""
        events = [e for e in self.snapshot.get("events", []) if q in str(e).lower()]
        put_rows(self.events_table, [(e.get("time"), e.get("src_ip"), e.get("domain"), e.get("query"), e.get("qtype"), e.get("length")) for e in events[:500]])

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = DNSHawkWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
