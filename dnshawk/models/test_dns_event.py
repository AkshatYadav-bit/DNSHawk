import tkinter as tk
from tkinter import ttk
from dnshawk.models.dns_event import DNSEvent


TEST_CASES = [
    {
        "name": "Normal A Query",
        "status": "NORMAL",
        "input": {
            "timestamp": "2026-09-29T10:30:15.123",
            "src_ip": "192.168.1.20",
            "dst_ip": "8.8.8.8",
            "query": "www.google.com.",
            "qtype": "A",
            "packet_length": 78,
            "response_length": 96,
            "rcode": "NOERROR"
        }
    },
    {
        "name": "NXDOMAIN Query",
        "status": "NXDOMAIN",
        "input": {
            "timestamp": "2026-09-29T10:30:16.456",
            "src_ip": "192.168.1.20",
            "dst_ip": "8.8.8.8",
            "query": "random12345.example.com.",
            "qtype": "A",
            "packet_length": 82,
            "response_length": 82,
            "rcode": "NXDOMAIN"
        }
    },
    {
        "name": "Query Without Response",
        "status": "NO RESPONSE",
        "input": {
            "timestamp": "2026-09-29T10:30:17.789",
            "src_ip": "192.168.1.20",
            "dst_ip": "192.168.1.1",
            "query": "abc123.test.local.",
            "qtype": "A",
            "packet_length": 70,
            "response_length": None,
            "rcode": None
        }
    }
]


class DNSHawkTestApp:

    def __init__(self, root):
        self.root = root

        root.title("DNSHawk | DNSEvent Processing Console")
        root.geometry("1150x760")
        root.minsize(1000, 650)

        self.bg = "#0b1120"
        self.panel = "#111827"
        self.panel2 = "#172033"
        self.text = "#e5e7eb"
        self.muted = "#94a3b8"
        self.accent = "#38bdf8"
        self.green = "#22c55e"
        self.yellow = "#facc15"
        self.red = "#ef4444"

        root.configure(bg=self.bg)

        self.setup_style()
        self.build_header()
        self.build_main()

        self.current_case = 0

        # self.root.after(500, self.process_current_case)

    # ---------------------------------------------------------
    # UI
    # ---------------------------------------------------------

    def setup_style(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Case.TCombobox",
            fieldbackground=self.panel2,
            background=self.panel2,
            foreground=self.text
        )

    def build_header(self):

        header = tk.Frame(
            self.root,
            bg=self.bg,
            height=80
        )

        header.pack(fill="x", padx=30, pady=(20, 5))

        title = tk.Label(
            header,
            text="DNSHawk",
            font=("Segoe UI", 25, "bold"),
            fg=self.accent,
            bg=self.bg
        )

        title.pack(side="left")

        subtitle = tk.Label(
            header,
            text="  |  DNSEvent Processing Console",
            font=("Segoe UI", 14),
            fg=self.muted,
            bg=self.bg
        )

        subtitle.pack(side="left", pady=(7, 0))

        self.status_label = tk.Label(
            header,
            text="● INITIALIZING",
            font=("Segoe UI", 10, "bold"),
            fg=self.yellow,
            bg=self.bg
        )

        self.status_label.pack(side="right", pady=10)

    def build_main(self):

        # Test selector
        selector_frame = tk.Frame(
            self.root,
            bg=self.bg
        )

        selector_frame.pack(
            fill="x",
            padx=30,
            pady=(5, 15)
        )

        tk.Label(
            selector_frame,
            text="TEST SCENARIO",
            font=("Segoe UI", 9, "bold"),
            fg=self.muted,
            bg=self.bg
        ).pack(side="left")

        self.case_var = tk.StringVar(
            value=TEST_CASES[0]["name"]
        )

        self.case_menu = ttk.Combobox(
            selector_frame,
            textvariable=self.case_var,
            values=[x["name"] for x in TEST_CASES],
            state="readonly",
            width=35
        )

        self.case_menu.pack(side="left", padx=15)

        self.run_button = tk.Button(
            selector_frame,
            text="RUN PROCESSING",
            command=self.start_processing,
            bg=self.accent,
            fg="#020617",
            activebackground="#7dd3fc",
            activeforeground="#020617",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=18,
            pady=7,
            cursor="hand2"
        )

        self.run_button.pack(side="left")

        # Main content
        content = tk.Frame(
            self.root,
            bg=self.bg
        )

        content.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 20)
        )

        # LEFT PANEL
        left = tk.Frame(
            content,
            bg=self.panel,
            highlightbackground="#243044",
            highlightthickness=1
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        self.build_input_panel(left)

        # RIGHT PANEL
        right = tk.Frame(
            content,
            bg=self.panel,
            highlightbackground="#243044",
            highlightthickness=1
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=(10, 0)
        )

        self.build_output_panel(right)

    def build_input_panel(self, parent):

        tk.Label(
            parent,
            text="RAW DNS INPUT",
            font=("Segoe UI", 11, "bold"),
            fg=self.text,
            bg=self.panel
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 3)
        )

        tk.Label(
            parent,
            text="Incoming DNS record before normalization",
            font=("Segoe UI", 9),
            fg=self.muted,
            bg=self.panel
        ).pack(
            anchor="w",
            padx=20
        )

        self.input_text = tk.Text(
            parent,
            height=14,
            bg="#0a0f1c",
            fg="#cbd5e1",
            insertbackground=self.text,
            font=("Consolas", 10),
            relief="flat",
            padx=15,
            pady=15
        )

        self.input_text.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        self.build_pipeline(parent)

    def build_pipeline(self, parent):

        tk.Label(
            parent,
            text="PROCESSING PIPELINE",
            font=("Segoe UI", 9, "bold"),
            fg=self.muted,
            bg=self.panel
        ).pack(
            anchor="w",
            padx=20,
            pady=(5, 8)
        )

        self.pipeline_labels = []

        stages = [
            "01  Parse timestamp / IP addresses",
            "02  Normalize DNS query",
            "03  Extract domain / subdomain",
            "04  Normalize query type / RCODE",
            "05  Calculate query metadata",
            "06  Build DNSEvent object"
        ]

        for stage in stages:

            label = tk.Label(
                parent,
                text="○  " + stage,
                font=("Consolas", 9),
                fg=self.muted,
                bg=self.panel,
                anchor="w"
            )

            label.pack(
                fill="x",
                padx=20,
                pady=2
            )

            self.pipeline_labels.append(label)

    def build_output_panel(self, parent):

        top = tk.Frame(
            parent,
            bg=self.panel
        )

        top.pack(
            fill="x",
            padx=20,
            pady=(18, 5)
        )

        tk.Label(
            top,
            text="STRUCTURED DNSEVENT",
            font=("Segoe UI", 11, "bold"),
            fg=self.text,
            bg=self.panel
        ).pack(side="left")

        self.result_badge = tk.Label(
            top,
            text="WAITING",
            font=("Segoe UI", 8, "bold"),
            fg=self.muted,
            bg=self.panel2,
            padx=10,
            pady=4
        )

        self.result_badge.pack(side="right")

        tk.Label(
            parent,
            text="Normalized event consumed by downstream DNSHawk modules",
            font=("Segoe UI", 9),
            fg=self.muted,
            bg=self.panel
        ).pack(
            anchor="w",
            padx=20
        )

        self.output_text = tk.Text(
            parent,
            height=22,
            bg="#0a0f1c",
            fg="#d1fae5",
            font=("Consolas", 10),
            relief="flat",
            padx=15,
            pady=15
        )

        self.output_text.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        self.output_text.config(state="disabled")

    # ---------------------------------------------------------
    # Processing
    # ---------------------------------------------------------

    def get_selected_case(self):

        selected = self.case_var.get()

        for case in TEST_CASES:
            if case["name"] == selected:
                return case

        return TEST_CASES[0]

    def start_processing(self):

        self.run_button.config(
            state="disabled"
        )

        self.current_case = 0

        self.reset_pipeline()

        self.status_label.config(
            text="● PROCESSING",
            fg=self.yellow
        )

        self.result_badge.config(
            text="PROCESSING",
            fg=self.yellow
        )

        case = self.get_selected_case()

        self.show_input(case)

        self.run_stage(0)

    def reset_pipeline(self):

        for label in self.pipeline_labels:

            label.config(
                text=label.cget("text").replace("✓  ", "○  "),
                fg=self.muted
            )

    def show_input(self, case):

        self.input_text.delete(
            "1.0",
            tk.END
        )

        for key, value in case["input"].items():

            self.input_text.insert(
                tk.END,
                f"{key:<18}: {value!r}\n"
            )

    def run_stage(self, index):

        if index >= len(self.pipeline_labels):

            self.finish_processing()

            return

        label = self.pipeline_labels[index]

        original = label.cget("text")

        label.config(
            text="◉  " + original[3:],
            fg=self.accent
        )

        self.root.after(
            350,
            lambda: self.complete_stage(index)
        )

    def complete_stage(self, index):

        label = self.pipeline_labels[index]

        original = label.cget("text")

        label.config(
            text="✓  " + original[3:],
            fg=self.green
        )

        self.root.after(
            150,
            lambda: self.run_stage(index + 1)
        )

    def finish_processing(self):

        case = self.get_selected_case()

        try:

            event = DNSEvent(
                timestamp=case["input"]["timestamp"],
                src_ip=case["input"]["src_ip"],
                dst_ip=case["input"]["dst_ip"],
                query=case["input"]["query"],
                qtype=case["input"]["qtype"],
                packet_length=case["input"]["packet_length"],
                response_length=case["input"]["response_length"],
                rcode=case["input"]["rcode"]
            )

            self.show_event(event)

            self.status_label.config(
                text="● PROCESSING COMPLETE",
                fg=self.green
            )

            self.result_badge.config(
                text="EVENT CREATED",
                fg=self.green
            )

        except Exception as e:

            self.output_text.config(
                state="normal"
            )

            self.output_text.delete(
                "1.0",
                tk.END
            )

            self.output_text.insert(
                tk.END,
                "PROCESSING ERROR\n\n"
                f"{type(e).__name__}: {e}"
            )

            self.output_text.config(
                state="disabled"
            )

            self.status_label.config(
                text="● PROCESSING FAILED",
                fg=self.red
            )

            self.result_badge.config(
                text="ERROR",
                fg=self.red
            )

        self.run_button.config(
            state="normal"
        )

    def show_event(self, event):

        output = (
            "DNSEvent {\n\n"
            f"  timestamp       : {event.timestamp}\n"
            f"  src_ip          : {event.src_ip}\n"
            f"  dst_ip          : {event.dst_ip}\n"
            f"  query           : {event.query}\n"
            f"  domain          : {event.domain}\n"
            f"  subdomain       : {event.subdomain}\n"
            f"  qtype           : {event.qtype}\n"
            f"  query_length    : {event.query_length}\n"
            f"  packet_length   : {event.packet_length}\n"
            f"  response_length : {event.response_length}\n"
            f"  rcode           : {event.rcode}\n"
            f"  is_nxdomain     : {event.is_nxdomain}\n\n"
            "}"
        )

        self.output_text.config(
            state="normal"
        )

        self.output_text.delete(
            "1.0",
            tk.END
        )

        self.output_text.insert(
            tk.END,
            output
        )

        self.output_text.config(
            state="disabled"
        )


root = tk.Tk()

app = DNSHawkTestApp(root)

root.mainloop()