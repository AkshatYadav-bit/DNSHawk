from tkinter import ttk


class FeaturePanel:
    """
    Displays features and rule-based detection
    information for the selected DNS window.
    """

    def __init__(self, parent):

        self.frame = ttk.LabelFrame(
            parent,
            text="Selected DNS Window Features",
            padding=12
        )

        # -------------------------------------------------
        # Selected window information
        # -------------------------------------------------

        self.selected_info_label = ttk.Label(
            self.frame,
            text="No window selected",
            font=("Segoe UI", 9, "bold"),
            wraplength=300
        )

        self.selected_info_label.pack(
            anchor="w",
            pady=(0, 10)
        )

        # -------------------------------------------------
        # Detection summary
        # -------------------------------------------------

        self.detection_summary_label = ttk.Label(
            self.frame,
            text="Detection: No window selected",
            font=("Segoe UI", 10, "bold"),
            wraplength=300
        )

        self.detection_summary_label.pack(
            anchor="w",
            pady=(0, 8)
        )

        # -------------------------------------------------
        # Individual rule status
        # -------------------------------------------------

        self.rule_status_labels = {}

        rule_display_names = {
            "long_subdomain":
                "Long Subdomain",

            "high_subdomain_entropy":
                "High Subdomain Entropy",

            "high_query_rate":
                "High Query Rate",

            "high_unique_subdomain_ratio":
                "High Unique Subdomain Ratio",

            "high_nxdomain_rate":
                "High NXDOMAIN Rate"
        }

        for rule_name, display_name in (
            rule_display_names.items()
        ):

            label = ttk.Label(
                self.frame,
                text=f"○ {display_name}",
                font=("Segoe UI", 9)
            )

            label.pack(
                anchor="w",
                pady=2
            )

            self.rule_status_labels[
                rule_name
            ] = label

        # -------------------------------------------------
        # Feature container
        # -------------------------------------------------

        feature_container = ttk.Frame(
            self.frame
        )

        feature_container.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        self.feature_labels = {}

        features = [
            ("query_count", "Queries"),

            ("unique_query_count",
             "Unique Queries"),

            ("unique_query_ratio",
             "Unique Query Ratio"),

            ("queries_per_second",
             "Queries / Second"),

            ("avg_query_length",
             "Avg Query Length"),

            ("max_query_length",
             "Max Query Length"),

            ("entropy",
             "Entropy"),

            ("avg_subdomain_length",
             "Avg Subdomain Length"),

            ("max_subdomain_length",
             "Max Subdomain Length"),

            ("avg_subdomain_entropy",
             "Avg Subdomain Entropy"),

            ("max_subdomain_entropy",
             "Max Subdomain Entropy"),

            ("unique_subdomain_count",
             "Unique Subdomains"),

            ("unique_subdomain_ratio",
             "Unique Subdomain Ratio"),

            ("nxdomain_rate",
             "NXDOMAIN Rate"),

            ("mean_interarrival",
             "Mean Interarrival"),

            ("std_interarrival",
             "Std Interarrival"),

            ("avg_packet_length",
             "Avg Packet Length"),

            ("max_packet_length",
             "Max Packet Length"),

            ("avg_response_length",
             "Avg Response Length")
        ]

        for row, (key, label) in enumerate(features):

            ttk.Label(
                feature_container,
                text=label + ":",
                font=("Segoe UI", 9)
            ).grid(
                row=row,
                column=0,
                sticky="w",
                pady=4
            )

            value_label = ttk.Label(
                feature_container,
                text="0",
                font=("Consolas", 9, "bold")
            )

            value_label.grid(
                row=row,
                column=1,
                sticky="e",
                padx=(15, 0),
                pady=4
            )

            self.feature_labels[
                key
            ] = value_label

    def update(
        self,
        window,
        features,
        detection
    ):
        """
        Update selected window information,
        detection status and features.
        """

        # -------------------------------------------------
        # Window information
        # -------------------------------------------------

        self.selected_info_label.config(
            text=(
                f"Source: {window.src_ip}\n"
                f"Domain: {window.domain}\n"
                f"Window: "
                f"{window.start_time.strftime('%H:%M:%S')}"
                f" - "
                f"{window.end_time.strftime('%H:%M:%S')}"
            )
        )

        # -------------------------------------------------
        # Detection information
        # -------------------------------------------------

        if detection is None:

            self.detection_summary_label.config(
                text="Detection: Not evaluated"
            )

            for rule_name, label in (
                self.rule_status_labels.items()
            ):

                display_name = (
                    rule_name
                    .replace("_", " ")
                    .title()
                )

                label.config(
                    text=f"○ {display_name}"
                )

        else:

            triggered_count = len(
                detection["triggered_rules"]
            )

            evidence_text = (
                "MET"
                if detection["minimum_evidence_met"]
                else "NOT MET"
            )

            self.detection_summary_label.config(
                text=(
                    f"Evidence: {evidence_text} | "
                    f"Score: "
                    f"{detection['score']:.1f}/"
                    f"{detection['max_score']:.1f} | "
                    f"Rules: "
                    f"{triggered_count}/5"
                )
            )

            for rule_name, result in (
                detection["rule_results"].items()
            ):

                label = self.rule_status_labels[
                    rule_name
                ]

                display_name = (
                    rule_name
                    .replace("_", " ")
                    .title()
                )

                value = result["value"]
                threshold = result["threshold"]

                if result["triggered"]:

                    label.config(
                        text=(
                            f"✓ {display_name}  "
                            f"({value:.3f} >= "
                            f"{threshold:.3f})"
                        )
                    )

                else:

                    label.config(
                        text=(
                            f"○ {display_name}  "
                            f"({value:.3f} < "
                            f"{threshold:.3f})"
                        )
                    )

        # -------------------------------------------------
        # Feature information
        # -------------------------------------------------

        for key, value in features.items():

            if key not in self.feature_labels:
                continue

            if isinstance(value, float):

                display_value = (
                    f"{value:.4f}"
                )

            else:

                display_value = str(
                    value
                )

            self.feature_labels[
                key
            ].config(
                text=display_value
            )