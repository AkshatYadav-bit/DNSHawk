from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time

from PySide6.QtCore import QThread, Signal

from dnshawk.collector.tshark_capture import TSharkCapture
from dnshawk.parser.dns_parser import parse_tshark_line
from dnshawk.aggregation.window import WindowManager
from dnshawk.features.feature_engine import FeatureEngine
from dnshawk.detection.rule_detector import RuleDetector
from dnshawk.detection.ml_detector import MLDetector


class CaptureWorker(QThread):
    snapshot = Signal(dict)
    status = Signal(str)
    error = Signal(str)

    def __init__(self, interface="6", tshark_path="tshark", parent=None):
        super().__init__(parent)
        self.interface = interface
        self.tshark_path = tshark_path
        self._stop_requested = False
        self.capture = None
        self.events = deque(maxlen=10000)
        self.query_rate = deque(maxlen=60)
        self.windows = {}
        self.last_emit = 0.0
        self.total_queries = 0
        self.feature_engine = FeatureEngine()
        self.rule_detector = RuleDetector()
        self.window_manager = WindowManager(window_size_seconds=60)
        self.ml_detector = None
        self.ml_error = None
        try:
            self.ml_detector = MLDetector()
        except Exception as exc:
            self.ml_error = str(exc)

    def stop(self):
        self._stop_requested = True
        if self.capture:
            self.capture.stop()

    def _evaluate(self, window):
        features = self.feature_engine.extract(window)
        rules = self.rule_detector.evaluate(features)
        triggered = [name for name, result in rules.items() if result.get("triggered")]
        rule_score = sum(float(r.get("weight", 1.0)) for r in rules.values() if r.get("triggered"))
        ml = None
        if self.ml_detector:
            try:
                ml = self.ml_detector.predict(features)
            except Exception as exc:
                ml = {"status": "error", "message": str(exc)}
        ml_suspicious = bool(ml and ml.get("prediction") == 1)
        rule_suspicious = len(triggered) >= 2
        suspicious = ml_suspicious or rule_suspicious
        probability = ml.get("probability") if ml else None
        reasons = []
        if ml_suspicious:
            reasons.append("XGBoost probability >= threshold")
        reasons.extend(triggered)
        return {
            "src_ip": window.src_ip, "domain": window.domain,
            "window_start": window.start_time.isoformat(),
            "query_count": window.query_count,
            "features": features, "rules": rules,
            "triggered_rules": triggered, "rule_score": rule_score,
            "ml": ml, "suspicious": suspicious,
            "probability": probability, "reasons": reasons,
            "detection_time": datetime.now(timezone.utc).isoformat()
        }

    def _make_snapshot(self, status):
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=1)
        events = [e for e in self.events if e.timestamp >= cutoff]
        counts = Counter(e.qtype or "OTHER" for e in events)
        suspicious = [d for d in self.windows.values()
                      if d["suspicious"] and
                      datetime.fromisoformat(d["detection_time"]) >= cutoff]
        suspicious.sort(key=lambda d: d["detection_time"], reverse=True)
        recent_events = [{
            "time": e.timestamp.strftime("%H:%M:%S"),
            "src_ip": e.src_ip or "-", "domain": e.domain or "-",
            "query": e.query, "qtype": e.qtype or "-", "length": e.query_length
        } for e in list(events)[-150:]][::-1]
        rate = list(self.query_rate)
        return {
            "status": status, "total_queries": self.total_queries,
            "queries_last_hour": len(events), "suspicious_count": len(suspicious),
            "alerts_count": len(suspicious), "query_rate": rate,
            "qtype_counts": dict(counts), "suspicious_domains": suspicious[:200],
            "events": recent_events,
            "windows": list(self.windows.values())[-500:][::-1],
            "ml_available": self.ml_detector is not None,
            "ml_error": self.ml_error
        }

    def run(self):
        self.status.emit(f"Starting capture on interface {self.interface}…")
        try:
            self.capture = TSharkCapture(self.interface, self.tshark_path)
            stream = self.capture.start()
            if stream is None:
                raise RuntimeError("TShark did not provide a readable output stream.")
            self.status.emit("Monitoring")
            bucket_second = int(time.time())
            bucket_count = 0
            while not self._stop_requested:
                line = stream.readline()
                if not line:
                    if self.capture and self.capture.process and self.capture.process.poll() is not None:
                        raise RuntimeError("TShark stopped. Check interface selection and permissions.")
                    self.msleep(20)
                    continue
                event = parse_tshark_line(line)
                if event is None:
                    continue
                self.total_queries += 1
                self.events.append(event)
                second = int(event.timestamp.timestamp())
                if second != bucket_second:
                    self.query_rate.append({"time": datetime.fromtimestamp(bucket_second, timezone.utc).strftime("%H:%M:%S"),
                                            "count": bucket_count})
                    bucket_second, bucket_count = second, 0
                bucket_count += 1
                key = (event.src_ip, event.domain, self.window_manager.get_window_start(event.timestamp))
                if key not in self.windows:
                    # Keep the UI's history bounded; this does not change model inference.
                    pass
                if key not in getattr(self, "_window_objects", {}):
                    if not hasattr(self, "_window_objects"):
                        self._window_objects = {}
                    from dnshawk.models.dns_window import DNSWindow
                    self._window_objects[key] = DNSWindow(event.src_ip, event.domain, key[2], 60, [])
                win = self._window_objects[key]
                win.add_event(event)
                detection = self._evaluate(win)
                detection["detection_time"] = datetime.now(timezone.utc).isoformat()
                self.windows["|".join(map(str, key))] = detection
                if len(self.windows) > 1000:
                    oldest = next(iter(self.windows))
                    self.windows.pop(oldest, None)
                now = time.monotonic()
                if now - self.last_emit >= 0.35:
                    self.snapshot.emit(self._make_snapshot("Monitoring"))
                    self.last_emit = now
            self.status.emit("Stopped")
        except Exception as exc:
            self.error.emit(str(exc))
            self.status.emit("Capture error")
        finally:
            if self.capture:
                self.capture.stop()
            self.snapshot.emit(self._make_snapshot("Stopped" if self._stop_requested else "Capture error"))
