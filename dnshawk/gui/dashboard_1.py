import queue

import threading

import tkinter as tk

from tkinter import ttk



from dnshawk.collector.tshark_capture import TSharkCapture

from dnshawk.parser.dns_parser import parse_tshark_line

from dnshawk.models.dns_window import DNSWindow

from dnshawk.features.feature_engine import FeatureEngine

from dnshawk.aggregation.window import WindowManager

from dnshawk.detection.rule_detector import RuleDetector

from dnshawk.detection.ml_detector import MLDetector



from dnshawk.gui.feature_panel_1 import FeaturePanel

from dnshawk.gui.kali_test import KaliTestPanel

from dnshawk.gui.header import HeaderPanel

from dnshawk.gui.controls import ControlPanel

from dnshawk.gui.event_panel import EventPanel

from dnshawk.gui.window_panel import WindowPanel





class DNSDashboard:

    """DNSHawk desktop dashboard with rule-based and ML detection."""



    def __init__(self, root):

        self.root = root

        self.root.title("DNSHawk | DNS Tunneling Detection")

        self.root.geometry("1440x850")

        self.root.minsize(1100, 680)

        self.root.configure(bg="#f3f5f8")



        self._configure_style()



        self.capture = None

        self.capture_thread = None

        self.running = False

        self.event_queue = queue.Queue()



        self.feature_engine = FeatureEngine()

        self.rule_detector = RuleDetector()

        self.window_manager = WindowManager(window_size_seconds=60)



        # Fail gracefully if the model artifact or dependency is unavailable.

        self.ml_detector = None

        self.ml_load_error = None

        try:

            self.ml_detector = MLDetector()

        except Exception as error:

            self.ml_load_error = str(error)



        self.windows = {}

        self.window_detections = {}

        self.selected_window_key = None

        self.total_events = 0



        self.build_interface()

        if self.ml_load_error:

            self.header.set_status("ML MODEL UNAVAILABLE", "#b45309")

            self.feature_panel.set_ml_unavailable(self.ml_load_error)



        self.root.protocol("WM_DELETE_WINDOW", self.close_application)

        self.root.after(200, self.process_events)



    def _configure_style(self):

        style = ttk.Style()

        try:

            style.theme_use("clam")

        except tk.TclError:

            pass



        style.configure("App.TFrame", background="#f3f5f8")

        style.configure("Card.TFrame", background="#ffffff")

        style.configure(

            "Title.TLabel", background="#ffffff", foreground="#172033",

            font=("Segoe UI", 17, "bold")

        )

        style.configure(

            "Subtitle.TLabel", background="#ffffff", foreground="#64748b",

            font=("Segoe UI", 9)

        )

        style.configure(

            "TLabelframe", background="#ffffff", bordercolor="#dbe2ea",

            relief="solid"

        )

        style.configure(

            "TLabelframe.Label", background="#ffffff",

            foreground="#263449", font=("Segoe UI", 10, "bold")

        )

        style.configure(

            "TNotebook", background="#f3f5f8", borderwidth=0

        )

        style.configure(

            "TNotebook.Tab", padding=(16, 9),

            font=("Segoe UI", 10, "bold")

        )

        style.map(

            "TNotebook.Tab",

            background=[("selected", "#ffffff"), ("!selected", "#e8edf4")],

            foreground=[("selected", "#1d4ed8"), ("!selected", "#475569")]

        )

        style.configure(

            "Treeview", rowheight=27, font=("Segoe UI", 9),

            background="#ffffff", fieldbackground="#ffffff",

            foreground="#1e293b"

        )

        style.configure(

            "Treeview.Heading", font=("Segoe UI", 9, "bold"),

            background="#eaf0f7", foreground="#263449", padding=(6, 7)

        )

        style.map("Treeview", background=[("selected", "#dbeafe")],

                  foreground=[("selected", "#172554")])

        style.configure("TButton", padding=(11, 6), font=("Segoe UI", 9))

        style.configure("TEntry", padding=5)



    def build_interface(self):

        shell = ttk.Frame(self.root, style="App.TFrame", padding=(12, 10, 12, 8))

        shell.pack(fill="both", expand=True)



        # Header card

        header_card = ttk.Frame(shell, style="Card.TFrame", padding=(16, 10))

        header_card.pack(fill="x", pady=(0, 8))

        title_area = ttk.Frame(header_card, style="Card.TFrame")

        title_area.pack(side="left", fill="x", expand=True)

        ttk.Label(

            title_area, text="DNSHawk", style="Title.TLabel"

        ).pack(anchor="w")

        ttk.Label(

            title_area,

            text="DNS traffic monitoring  •  Rule-based + XGBoost detection",

            style="Subtitle.TLabel"

        ).pack(anchor="w", pady=(2, 0))



        self.header = HeaderPanel(header_card)

        self.header.frame.pack(side="right", fill="y")

        self.header.title_label.pack_forget()



        # Capture controls in a dedicated card

        controls_card = ttk.LabelFrame(shell, text="Capture", padding=(10, 7))

        controls_card.pack(fill="x", pady=(0, 8))

        self.controls = ControlPanel(

            controls_card, start_callback=self.start_capture,

            stop_callback=self.stop_capture

        )

        self.controls.frame.pack(side="left", fill="x", expand=True)

        self.kali_test = KaliTestPanel(

            controls_card, start_callback=self.start_kali_test,

            stop_callback=self.stop_kali_test

        )

        self.kali_test.frame.configure(

            text="Kali VM test", padx=8, pady=5

        )

        self.kali_test.frame.pack(side="right", fill="x", padx=(8, 0))

        # Keep Clear Screens beside the capture controls for quick access.
        self.clear_button = ttk.Button(
            controls_card, text="Clear Screens", command=self.clear_screens,
            state="disabled"
        )
        self.clear_button.pack(side="right", padx=(8, 0), pady=2)

        # Reduce nested padding so the control bar stays compact.

        self.controls.frame.configure(padding=(4, 2, 4, 2))



        # Notebook prevents three dense panels competing for width.

        self.notebook = ttk.Notebook(shell)

        self.notebook.pack(fill="both", expand=True, pady=(0, 8))



        events_tab = ttk.Frame(self.notebook, padding=8)

        windows_tab = ttk.Frame(self.notebook, padding=8)

        analysis_tab = ttk.Frame(self.notebook, padding=8)

        self.notebook.add(events_tab, text="Live DNS Events")

        self.notebook.add(windows_tab, text="DNS Windows")

        self.notebook.add(analysis_tab, text="Window Analysis")



        self.event_panel = EventPanel(events_tab)

        self.event_panel.frame.pack(fill="both", expand=True)



        self.window_panel = WindowPanel(

            windows_tab, selection_callback=self.on_window_selected

        )

        self.window_panel.frame.pack(fill="both", expand=True)



        self.feature_panel = FeaturePanel(analysis_tab)

        self.feature_panel.frame.pack(fill="both", expand=True)



        # Status bar

        status = ttk.Frame(shell, style="Card.TFrame", padding=(10, 6))

        status.pack(fill="x")

        self.event_count_label = ttk.Label(

            status, text="Events captured: 0", background="#ffffff",

            foreground="#334155", font=("Segoe UI", 9)

        )

        self.event_count_label.pack(side="left")

        ttk.Label(

            status, text="Window: 60 seconds  |  ML minimum: 10 queries",

            background="#ffffff", foreground="#64748b",

            font=("Segoe UI", 9)

        ).pack(side="right", padx=(8, 0))




    def start_capture(self):

        if self.running:

            return

        try:

            interface = self.controls.get_interface()

        except ValueError:

            self.header.set_status("INVALID INTERFACE", "#b91c1c")

            return

        self._start_capture_on_interface(interface, source="normal")



    def start_kali_test(self, interface):

        if self.running:

            return

        self._start_capture_on_interface(interface, source="kali")



    def _start_capture_on_interface(self, interface, source):

        self.capture = TSharkCapture(interface)

        try:

            stream = self.capture.start()

        except Exception as error:

            self.header.set_status(f"CAPTURE ERROR: {error}", "#b91c1c")

            self.capture = None

            return



        self.running = True

        self.clear_button.config(state="disabled")

        if source == "kali":

            self.kali_test.set_running()

            self.controls.start_button.config(state="disabled")

        else:

            self.controls.set_running()

            self.kali_test.start_button.config(state="disabled")



        self.header.set_status(

            "CAPTURING — KALI TEST" if source == "kali" else "CAPTURING",

            "#15803d"

        )

        self.capture_thread = threading.Thread(

            target=self.capture_loop, args=(stream,), daemon=True

        )

        self.capture_thread.start()



    def stop_capture(self):

        self._stop_capture("STOPPED")



    def stop_kali_test(self):

        self._stop_capture("KALI TEST STOPPED")



    def _stop_capture(self, message):

        if not self.running:

            return

        self.running = False

        if self.capture is not None:

            try:

                self.capture.stop()

            except Exception:

                pass

        self.capture = None

        self.controls.set_stopped()

        self.kali_test.set_stopped()

        self.clear_button.config(state="normal")

        self.header.set_status(message, "#64748b")



    def clear_screens(self):

        """Clear displayed capture results and reset the dashboard for a new run."""

        if self.running:

            self.header.set_status("STOP CAPTURE BEFORE CLEARING", "#b45309")

            return



        # Remove any events that arrived just before capture stopped.

        while True:

            try:

                self.event_queue.get_nowait()

            except queue.Empty:

                break



        # Clear all tables in the event and window panels without relying on

        # their internal widget attribute names.

        for panel in (self.event_panel, self.window_panel):

            self._clear_treeviews(panel.frame)



        self.windows.clear()

        self.window_detections.clear()

        self.selected_window_key = None

        self.total_events = 0

        self.event_count_label.config(text="Events captured: 0")



        if hasattr(self.feature_panel, "clear"):

            self.feature_panel.clear()

        elif hasattr(self.feature_panel, "selected_info_label"):
            self.feature_panel.selected_info_label.config(
                text="Select a DNS window to inspect it"
            )



        self.header.set_status("SCREENS CLEARED", "#64748b")

        self.clear_button.config(state="disabled")



    @staticmethod

    def _clear_treeviews(widget):

        """Delete rows from every ttk.Treeview nested inside a panel."""

        if isinstance(widget, ttk.Treeview):

            children = widget.get_children("")

            if children:

                widget.delete(*children)

            return

        for child in widget.winfo_children():

            DNSDashboard._clear_treeviews(child)



    def capture_loop(self, stream):

        try:

            for line in stream:

                if not self.running:

                    break

                event = parse_tshark_line(line)

                if event is not None:

                    self.event_queue.put(event)

        except Exception as error:

            # Never update Tk widgets from the capture thread.

            self.event_queue.put(("capture_error", str(error)))



    def process_events(self):

        while True:

            try:

                item = self.event_queue.get_nowait()

            except queue.Empty:

                break

            if isinstance(item, tuple) and item and item[0] == "capture_error":

                self.header.set_status(f"CAPTURE STREAM ERROR: {item[1]}", "#b91c1c")

                continue

            self.handle_event(item)

        self.root.after(200, self.process_events)



    def handle_event(self, event):

        self.total_events += 1

        self.event_panel.insert_event(event)



        window_start = self.window_manager.get_window_start(event.timestamp)

        key = (event.src_ip, event.domain, window_start)



        if key not in self.windows:

            self.windows[key] = DNSWindow(

                src_ip=event.src_ip, domain=event.domain,

                start_time=window_start, window_size_seconds=60

            )

            self.window_panel.add_window(key, self.windows[key])

            self.window_detections[key] = None



        window = self.windows[key]

        window.add_event(event)

        features = self.feature_engine.extract(window)



        # Keep the existing rule detector; add ML as an independent result.

        detection = self.rule_detector.assess(features)

        if self.ml_detector is not None:

            try:

                detection["ml_detection"] = self.ml_detector.predict(features)

            except Exception as error:

                detection["ml_detection"] = {

                    "status": "error", "message": str(error),

                    "query_count": features.get("query_count", 0),

                    "prediction": None, "probability": None,

                    "threshold": 0.5,

                }

        else:

            detection["ml_detection"] = {

                "status": "unavailable",

                "message": self.ml_load_error or "Model unavailable",

                "query_count": features.get("query_count", 0),

                "prediction": None, "probability": None, "threshold": 0.5,

            }



        self.window_detections[key] = detection

        self.window_panel.update_window(key, window, detection)



        if self.selected_window_key is None:

            self.selected_window_key = key

            self.window_panel.select_window(key)

            self.notebook.select(2)



        if self.selected_window_key == key:

            self.update_selected_window()



        self.event_count_label.config(text=f"Events captured: {self.total_events}")



    def on_window_selected(self, key):

        if key not in self.windows:

            return

        self.selected_window_key = key

        self.update_selected_window()

        self.notebook.select(2)



    def update_selected_window(self):

        key = self.selected_window_key

        if key is None or key not in self.windows:

            return

        window = self.windows[key]

        features = self.feature_engine.extract(window)

        detection = self.window_detections.get(key)

        self.feature_panel.update(window, features, detection)



    def close_application(self):

        self.running = False

        if self.capture is not None:

            try:

                self.capture.stop()

            except Exception:

                pass

            self.capture = None

        self.root.destroy()





def main():

    root = tk.Tk()

    DNSDashboard(root)

    root.mainloop()





if __name__ == "__main__":

    main()
