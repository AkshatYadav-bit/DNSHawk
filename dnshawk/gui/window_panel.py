from tkinter import ttk


class WindowPanel:
    """
    Displays DNS aggregation windows and
    their rule-based detection results.
    """

    def __init__(
        self,
        parent,
        selection_callback
    ):

        self.selection_callback = (
            selection_callback
        )

        self.frame = ttk.LabelFrame(
            parent,
            text="DNS Windows",
            padding=8
        )

        window_columns = (
            "source",
            "domain",
            "start",
            "events",
            "rules",
            "score"
        )

        self.table = ttk.Treeview(
            self.frame,
            columns=window_columns,
            show="headings",
            selectmode="browse"
        )

        window_headings = {
            "source": "Source",
            "domain": "Domain",
            "start": "Start",
            "events": "Events",
            "rules": "Rules",
            "score": "Score"
        }

        window_widths = {
            "source": 115,
            "domain": 180,
            "start": 75,
            "events": 60,
            "rules": 60,
            "score": 65
        }

        for column in window_columns:

            self.table.heading(
                column,
                text=window_headings[column]
            )

            self.table.column(
                column,
                width=window_widths[column],
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            self.frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        self.table.bind(
            "<<TreeviewSelect>>",
            self._on_selected
        )

        # Maps unique window key -> Treeview item ID
        self.items = {}

    def add_window(self, key, window):
        """
        Add a new DNS window to the table.
        """

        item_id = self.table.insert(
            "",
            "end",
            values=(
                window.src_ip,
                window.domain,
                window.start_time.strftime(
                    "%H:%M:%S"
                ),
                0,
                "0/5",
                "0.0"
            )
        )

        self.items[key] = item_id

        return item_id

    def update_window(
        self,
        key,
        window,
        detection
    ):
        """
        Update an existing DNS window row
        with event count and detection results.
        """

        item_id = self.items[key]

        if detection is None:

            triggered_count = 0
            score = 0.0

        else:

            triggered_count = len(
                detection["triggered_rules"]
            )

            score = detection["score"]

        self.table.item(
            item_id,
            values=(
                window.src_ip,
                window.domain,
                window.start_time.strftime(
                    "%H:%M:%S"
                ),
                window.event_count,
                f"{triggered_count}/5",
                f"{score:.1f}"
            )
        )

    def select_window(self, key):
        """
        Select a window programmatically.
        """

        if key not in self.items:
            return

        item_id = self.items[key]

        self.table.selection_set(
            item_id
        )

        self.table.focus(
            item_id
        )

    def _on_selected(self, event):
        """
        Handle user selecting a DNS window.
        """

        selection = self.table.selection()

        if not selection:
            return

        item_id = selection[0]

        for key, stored_item_id in self.items.items():

            if stored_item_id == item_id:

                self.selection_callback(
                    key
                )

                break