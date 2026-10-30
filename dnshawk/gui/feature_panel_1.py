from tkinter import ttk


class FeaturePanel:
    """Window analysis panel: rule evidence, ML output, and features."""

    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(2, weight=1)

        self.selected_info_label = ttk.Label(
            self.frame, text="Select a DNS window to inspect it",
            font=("Segoe UI", 10, "bold"), justify="left"
        )
        self.selected_info_label.grid(
            row=0, column=0, sticky="ew", padx=4, pady=(2, 8)
        )

        summary = ttk.LabelFrame(self.frame, text="Detection Summary", padding=10)
        summary.grid(row=1, column=0, sticky="ew", padx=2, pady=(0, 8))
        summary.columnconfigure(0, weight=1)

        self.detection_summary_label = ttk.Label(
            summary, text="Rules: Not evaluated", font=("Segoe UI", 10, "bold")
        )
        self.detection_summary_label.grid(row=0, column=0, sticky="w")

        self.ml_summary_label = ttk.Label(
            summary, text="ML: Not evaluated", font=("Segoe UI", 10, "bold"),
            justify="left"
        )
        self.ml_summary_label.grid(row=1, column=0, sticky="w", pady=(6, 0))

        # Rule checks and feature values share a two-column layout.
        lower = ttk.Frame(self.frame)
        lower.grid(row=2, column=0, sticky="nsew")
        lower.columnconfigure(0, weight=1, uniform="analysis")
        lower.columnconfigure(1, weight=1, uniform="analysis")
        lower.rowconfigure(0, weight=1)

        rules_frame = ttk.LabelFrame(lower, text="Rule Checks", padding=10)
        rules_frame.grid(row=0, column=0, sticky="nsew", padx=(2, 5))
        features_frame = ttk.LabelFrame(lower, text="Window Features", padding=10)
        features_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 2))

        rule_display_names = {
            "long_subdomain": "Long subdomain",
            "high_subdomain_entropy": "High subdomain entropy",
            "high_query_rate": "High query rate",
            "high_unique_subdomain_ratio": "Unique subdomain ratio",
            "high_nxdomain_rate": "High NXDOMAIN rate",
        }
        self.rule_status_labels = {}
        for row, (name, display) in enumerate(rule_display_names.items()):
            label = ttk.Label(
                rules_frame, text=f"○ {display}", wraplength=340,
                font=("Segoe UI", 9)
            )
            label.grid(row=row, column=0, sticky="w", pady=5)
            self.rule_status_labels[name] = label

        features_frame.columnconfigure(1, weight=1)
        self.feature_labels = {}
        features = [
            ("query_count", "Queries"),
            ("unique_query_count", "Unique queries"),
            ("unique_query_ratio", "Unique query ratio"),
            ("queries_per_second", "Queries / second"),
            ("avg_query_length", "Average query length"),
            ("max_query_length", "Maximum query length"),
            ("entropy", "Query entropy"),
            ("avg_subdomain_length", "Average subdomain length"),
            ("max_subdomain_length", "Maximum subdomain length"),
            ("avg_subdomain_entropy", "Average subdomain entropy"),
            ("max_subdomain_entropy", "Maximum subdomain entropy"),
            ("unique_subdomain_count", "Unique subdomains"),
            ("unique_subdomain_ratio", "Unique subdomain ratio"),
            ("nxdomain_rate", "NXDOMAIN rate"),
            ("mean_interarrival", "Mean inter-arrival"),
            ("std_interarrival", "Inter-arrival std. dev."),
            ("avg_packet_length", "Average packet length"),
            ("max_packet_length", "Maximum packet length"),
            ("avg_response_length", "Average response length"),
        ]
        for row, (key, display) in enumerate(features):
            ttk.Label(
                features_frame, text=display, font=("Segoe UI", 9)
            ).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 8))
            value_label = ttk.Label(
                features_frame, text="—", font=("Consolas", 9, "bold")
            )
            value_label.grid(row=row, column=1, sticky="e", pady=3)
            self.feature_labels[key] = value_label

    def clear(self):
        """Reset the analysis panel after the dashboard screens are cleared."""
        self.selected_info_label.config(text="Select a DNS window to inspect it")
        self.detection_summary_label.config(text="Rules: Not evaluated")
        self.ml_summary_label.config(text="ML: Not evaluated")
        rule_display_names = {
            "long_subdomain": "Long subdomain",
            "high_subdomain_entropy": "High subdomain entropy",
            "high_query_rate": "High query rate",
            "high_unique_subdomain_ratio": "High unique subdomain ratio",
            "high_nxdomain_rate": "High NXDOMAIN rate",
        }
        for name, label in self.rule_status_labels.items():
            label.config(text=f"○ {rule_display_names.get(name, name.replace('_', ' ').title())}")
        for label in self.feature_labels.values():
            label.config(text="—")

    def set_ml_unavailable(self, message):
        self.ml_summary_label.config(
            text=f"ML model unavailable: {message}"
        )

    def update(self, window, features, detection):
        self.selected_info_label.config(
            text=(
                f"Source: {window.src_ip}     Domain: {window.domain}\n"
                f"Window: {window.start_time.strftime('%H:%M:%S')} – "
                f"{window.end_time.strftime('%H:%M:%S')}     "
                f"Events: {window.event_count}"
            )
        )

        if detection is None:
            self.detection_summary_label.config(text="Rules: Not evaluated")
            for name, label in self.rule_status_labels.items():
                label.config(text=f"○ {name.replace('_', ' ').title()}")
            self.ml_summary_label.config(text="ML: Not evaluated")
        else:
            triggered = len(detection.get("triggered_rules", []))
            evidence = "MET" if detection.get("minimum_evidence_met") else "NOT MET"
            self.detection_summary_label.config(
                text=(
                    f"Rule evidence: {evidence}    "
                    f"Score: {detection.get('score', 0):.1f}/"
                    f"{detection.get('max_score', 0):.1f}    "
                    f"Triggered: {triggered}/5"
                )
            )
            for name, result in detection.get("rule_results", {}).items():
                label = self.rule_status_labels.get(name)
                if label is None:
                    continue
                display = name.replace("_", " ").title()
                value = result.get("value", 0)
                threshold = result.get("threshold", 0)
                mark = "✓" if result.get("triggered") else "○"
                relation = ">=" if result.get("triggered") else "<"
                label.config(
                    text=f"{mark} {display}: {value:.3f} {relation} {threshold:.3f}"
                )

            ml = detection.get("ml_detection")
            if not ml:
                self.ml_summary_label.config(text="ML: Not evaluated")
            elif ml.get("status") == "insufficient_evidence":
                self.ml_summary_label.config(
                    text=f"ML: Insufficient evidence ({ml.get('query_count', 0)}/10 queries)"
                )
            elif ml.get("status") == "classified":
                self.ml_summary_label.config(
                    text=(
                        f"ML classification: {ml.get('label', 'unknown').replace('_', ' ').title()}\n"
                        f"Tunneling probability: {ml.get('probability', 0) * 100:.2f}%  "
                        f"(decision threshold {ml.get('threshold', 0.5):.2f})"
                    )
                )
            else:
                self.ml_summary_label.config(
                    text=f"ML unavailable/error: {ml.get('message', ml.get('status', 'unknown'))}"
                )

        for key, label in self.feature_labels.items():
            value = features.get(key, "—")
            label.config(
                text=f"{value:.4f}" if isinstance(value, float) else str(value)
            )
