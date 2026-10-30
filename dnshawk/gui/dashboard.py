import queue
import threading
import tkinter as tk

from dnshawk.collector.tshark_capture import TSharkCapture
from dnshawk.parser.dns_parser import parse_tshark_line
from dnshawk.models.dns_window import DNSWindow
from dnshawk.features.feature_engine import FeatureEngine
from dnshawk.aggregation.window import WindowManager
from dnshawk.detection.rule_detector import RuleDetector

from dnshawk.gui.feature_panel import FeaturePanel
from dnshawk.gui.kali_test import KaliTestPanel
from dnshawk.gui.header import HeaderPanel
from dnshawk.gui.controls import ControlPanel
from dnshawk.gui.event_panel import EventPanel
from dnshawk.gui.window_panel import WindowPanel
from dnshawk.gui.feature_panel import FeaturePanel


class DNSDashboard:
    """
    Main DNSHawk dashboard coordinator.

    Responsibilities:
    - Capture lifecycle
    - Event queue
    - DNS window state
    - Feature extraction
    - Rule-based detection
    - Communication between GUI panels
    """

    def __init__(self, root):

        self.root = root

        self.root.title(
            "DNSHawk - DNS Traffic Monitor"
        )

        self.root.geometry(
            "1450x750"
        )

        # -------------------------------------------------
        # Capture state
        # -------------------------------------------------

        self.capture = None
        self.capture_thread = None
        self.running = False

        # Queue safely transfers events from
        # capture thread to Tkinter thread.
        self.event_queue = queue.Queue()

        # -------------------------------------------------
        # DNS processing
        # -------------------------------------------------

        self.feature_engine = FeatureEngine()

        self.rule_detector = RuleDetector()

        self.window_manager = WindowManager(
            window_size_seconds=60
        )

        # -------------------------------------------------
        # DNS windows
        # -------------------------------------------------

        # Key:
        # (src_ip, domain, window_start)

        self.windows = {}

        # Key -> detection result
        self.window_detections = {}

        # Currently selected window
        self.selected_window_key = None

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.total_events = 0

        # -------------------------------------------------
        # Build GUI
        # -------------------------------------------------

        self.build_interface()

        # Start queue polling
        self.root.after(
            200,
            self.process_events
        )

    # =====================================================
    # BUILD GUI
    # =====================================================

    def build_interface(self):

        # -------------------------------------------------
        # Header
        # -------------------------------------------------

        self.header = HeaderPanel(
            self.root
        )

        # -------------------------------------------------
        # Controls
        # -------------------------------------------------

        self.controls = ControlPanel(
            self.root,
            start_callback=self.start_capture,
            stop_callback=self.stop_capture
        )

        # kali test controls

        self.kali_test = KaliTestPanel(
            self.root,
            start_callback=self.start_kali_test,
            stop_callback=self.stop_kali_test
        )

        self.kali_test.frame.pack(
            fill="x",
            padx=10,
            pady=(0, 5)
        )

        # -------------------------------------------------
        # Main three-panel area
        # -------------------------------------------------

        main = tk.PanedWindow(
            self.root,
            orient="horizontal"
        )

        main.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # -------------------------------------------------
        # Panel 1: Live DNS Events
        # -------------------------------------------------

        self.event_panel = EventPanel(
            main
        )

        main.add(
            self.event_panel.frame,
            stretch="always"
        )

        # -------------------------------------------------
        # Panel 2: DNS Windows
        # -------------------------------------------------

        self.window_panel = WindowPanel(
            main,
            selection_callback=self.on_window_selected
        )

        main.add(
            self.window_panel.frame,
            stretch="always"
        )

        # -------------------------------------------------
        # Panel 3: Features + Detection
        # -------------------------------------------------

        self.feature_panel = FeaturePanel(
            main
        )

        main.add(
            self.feature_panel.frame,
            stretch="always"
        )

        # -------------------------------------------------
        # Bottom status
        # -------------------------------------------------

        self.event_count_label = tk.Label(
            self.root,
            text="Events captured: 0",
            padx=8,
            pady=5
        )

        self.event_count_label.pack(
            anchor="w"
        )

    # =====================================================
    # START CAPTURE
    # =====================================================

    def start_capture(self):

        if self.running:
            return

        try:

            interface = (
                self.controls
                .get_interface()
            )

        except ValueError:

            self.header.set_status(
                "● INVALID INTERFACE",
                "red"
            )

            return

        self.capture = TSharkCapture(
            interface
        )

        try:

            stream = self.capture.start()

        except Exception as error:

            self.header.set_status(
                f"● ERROR: {error}",
                "red"
            )

            self.capture = None

            return

        self.running = True

        self.controls.set_running()

        self.header.set_status(
            "● CAPTURING",
            "green"
        )

        self.capture_thread = threading.Thread(
            target=self.capture_loop,
            args=(stream,),
            daemon=True
        )

        self.capture_thread.start()

    def start_kali_test(self, interface):

        if self.running:
            return

        self.capture = TSharkCapture(
            interface
        )

        try:
            stream = self.capture.start()

        except Exception as error:

            self.header.set_status(
                f"● KALI TEST ERROR: {error}",
                "red"
            )

            self.capture = None
            return

        self.running = True

        self.kali_test.set_running()

        self.header.set_status(
            "● KALI TEST CAPTURING",
            "green"
        )

        self.capture_thread = threading.Thread(
            target=self.capture_loop,
            args=(stream,),
            daemon=True
        )

        self.capture_thread.start()

    # =====================================================
    # STOP CAPTURE
    # =====================================================

    def stop_capture(self):

        if not self.running:
            return

        self.running = False

        if self.capture is not None:
            self.capture.stop()

        self.capture = None

        self.controls.set_stopped()
        self.kali_test.set_stopped()

        self.header.set_status(
            "● STOPPED",
            "red"
        )

    def stop_kali_test(self):

        if not self.running:
            return

        self.running = False

        if self.capture is not None:
            self.capture.stop()

        self.capture = None

        self.kali_test.set_stopped()

        self.header.set_status(
            "● KALI TEST STOPPED",
            "red"
        )

    # =====================================================
    # BACKGROUND CAPTURE THREAD
    # =====================================================

    def capture_loop(self, stream):

        try:

            for line in stream:

                if not self.running:
                    break

                event = parse_tshark_line(
                    line
                )

                if event is not None:

                    self.event_queue.put(
                        event
                    )

        except Exception:
            # Capture thread should not crash
            # the GUI.
            pass

    # =====================================================
    # PROCESS EVENT QUEUE
    # =====================================================

    def process_events(self):

        while True:

            try:

                event = (
                    self.event_queue
                    .get_nowait()
                )

            except queue.Empty:

                break

            self.handle_event(
                event
            )

        self.root.after(
            200,
            self.process_events
        )

    # =====================================================
    # HANDLE ONE DNS EVENT
    # =====================================================

    def handle_event(self, event):

        self.total_events += 1

        # -------------------------------------------------
        # 1. Add event to live event panel
        # -------------------------------------------------

        self.event_panel.insert_event(
            event
        )

        # -------------------------------------------------
        # 2. Determine fixed 60-second window
        # -------------------------------------------------

        window_start = (
            self.window_manager
            .get_window_start(
                event.timestamp
            )
        )

        # -------------------------------------------------
        # 3. Build unique window key
        # -------------------------------------------------

        key = (
            event.src_ip,
            event.domain,
            window_start
        )

        # -------------------------------------------------
        # 4. Create window if needed
        # -------------------------------------------------

        if key not in self.windows:

            self.windows[key] = DNSWindow(
                src_ip=event.src_ip,
                domain=event.domain,
                start_time=window_start,
                window_size_seconds=60
            )

            self.window_panel.add_window(
                key,
                self.windows[key]
            )

            # Detection does not exist yet.
            self.window_detections[key] = None

        # -------------------------------------------------
        # 5. Add event to correct window
        # -------------------------------------------------

        window = self.windows[key]

        window.add_event(
            event
        )

        # -------------------------------------------------
        # 6. Extract features
        # -------------------------------------------------

        features = (
            self.feature_engine
            .extract(window)
        )

        # -------------------------------------------------
        # 7. Run rule-based detection
        # -------------------------------------------------

        detection = (
            self.rule_detector
            .assess(features)
        )

        self.window_detections[key] = (
            detection
        )

        # -------------------------------------------------
        # 8. Update window panel
        # -------------------------------------------------

        self.window_panel.update_window(
            key,
            window,
            detection
        )

        # -------------------------------------------------
        # 9. Automatically select first window
        # -------------------------------------------------

        if self.selected_window_key is None:

            self.selected_window_key = key

            self.window_panel.select_window(
                key
            )

        # -------------------------------------------------
        # 10. Refresh selected window
        # -------------------------------------------------

        if self.selected_window_key == key:

            self.update_selected_window()

        # -------------------------------------------------
        # 11. Update event count
        # -------------------------------------------------

        self.event_count_label.config(
            text=(
                f"Events captured: "
                f"{self.total_events}"
            )
        )

    # =====================================================
    # WINDOW SELECTION
    # =====================================================

    def on_window_selected(self, key):

        if key not in self.windows:
            return

        self.selected_window_key = key

        self.update_selected_window()

    # =====================================================
    # UPDATE SELECTED WINDOW
    # =====================================================

    def update_selected_window(self):

        if self.selected_window_key is None:
            return

        if self.selected_window_key not in self.windows:
            return

        window = self.windows[
            self.selected_window_key
        ]

        # -------------------------------------------------
        # Extract current features
        # -------------------------------------------------

        features = (
            self.feature_engine
            .extract(window)
        )

        # -------------------------------------------------
        # Get current detection
        # -------------------------------------------------

        detection = (
            self.window_detections
            .get(
                self.selected_window_key
            )
        )

        # -------------------------------------------------
        # Update feature panel
        # -------------------------------------------------

        self.feature_panel.update(
            window,
            features,
            detection
        )

    # =====================================================
    # CLOSE APPLICATION
    # =====================================================

    def close_application(self):

        self.running = False

        if self.capture is not None:

            self.capture.stop()

            self.capture = None

        self.root.destroy()


# =========================================================
# MAIN
# =========================================================

def main():

    root = tk.Tk()

    dashboard = DNSDashboard(
        root
    )

    root.protocol(
        "WM_DELETE_WINDOW",
        dashboard.close_application
    )

    root.mainloop()


if __name__ == "__main__":
    main()