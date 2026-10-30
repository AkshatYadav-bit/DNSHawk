from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QPainter, QPen, QBrush, QFont
from PySide6.QtWidgets import QWidget


class LineChart(QWidget):
    def __init__(self, title="DNS queries per second", parent=None):
        super().__init__(parent)
        self.title = title
        self.points = []
        self.setMinimumHeight(220)

    def set_points(self, points):
        self.points = list(points)[-60:]
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor("#111827"))
        p.setPen(QColor("#e5e7eb"))
        p.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        p.drawText(18, 26, self.title)
        area = QRectF(42, 48, max(20, self.width()-62), max(30, self.height()-82))
        p.setPen(QPen(QColor("#293548"), 1))
        for i in range(4):
            y = area.top() + i * area.height()/3
            p.drawLine(int(area.left()), int(y), int(area.right()), int(y))
        vals = [max(0, int(x.get("count", 0))) for x in self.points]
        maxv = max(vals, default=1) or 1
        if len(vals) >= 2:
            from PySide6.QtCore import QPointF
            pen = QPen(QColor("#38bdf8"), 2)
            p.setPen(pen)
            pts = []
            for i, value in enumerate(vals):
                x = area.left() + i * area.width()/(len(vals)-1)
                y = area.bottom() - (value/maxv)*area.height()
                pts.append(QPointF(x, y))
            for a, b in zip(pts, pts[1:]):
                p.drawLine(a, b)
            p.setBrush(QColor("#38bdf8"))
            for pt in pts[-5:]:
                p.drawEllipse(pt, 2.5, 2.5)
        p.setPen(QColor("#94a3b8"))
        p.setFont(QFont("Segoe UI", 8))
        p.drawText(10, int(area.bottom()+24), "older")
        p.drawText(int(area.right()-34), int(area.bottom()+24), "now")
        p.end()


class DonutPlaceholder(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.counts = {}
        self.setMinimumHeight(220)

    def set_counts(self, counts):
        self.counts = counts or {}
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor("#111827"))
        p.setPen(QColor("#e5e7eb"))
        p.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        p.drawText(18, 26, "DNS query types")
        if not self.counts:
            p.setPen(QColor("#94a3b8"))
            p.drawText(18, 70, "Waiting for DNS queries…")
        else:
            total = sum(self.counts.values()) or 1
            y = 58
            for key, value in sorted(self.counts.items(), key=lambda x: -x[1])[:7]:
                p.setPen(QColor("#38bdf8"))
                p.drawText(20, y, f"{key}")
                p.setPen(QColor("#cbd5e1"))
                p.drawText(110, y, f"{value}  ({value/total:.0%})")
                y += 24
        p.end()
