from tkinter import ttk


class EventPanel:
    """
    Displays live DNS events.
    """

    def __init__(self, parent):

        self.frame = ttk.LabelFrame(
            parent,
            text="Live DNS Events",
            padding=8
        )

        event_columns = (
            "time",
            "src",
            "dst",
            "query",
            "qtype",
            "length"
        )

        self.table = ttk.Treeview(
            self.frame,
            columns=event_columns,
            show="headings"
        )

        event_headings = {
            "time": "Time",
            "src": "Source",
            "dst": "Destination",
            "query": "Query",
            "qtype": "Type",
            "length": "Length"
        }

        event_widths = {
            "time": 80,
            "src": 125,
            "dst": 125,
            "query": 260,
            "qtype": 55,
            "length": 65
        }

        for column in event_columns:

            self.table.heading(
                column,
                text=event_headings[column]
            )

            self.table.column(
                column,
                width=event_widths[column],
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

    def insert_event(self, event):
        """
        Add one DNS event to the table.
        """

        timestamp = event.timestamp.strftime(
            "%H:%M:%S"
        )

        self.table.insert(
            "",
            "end",
            values=(
                timestamp,
                event.src_ip,
                event.dst_ip,
                event.query,
                event.qtype,
                event.packet_length
            )
        )

        # Keep only latest 200 displayed events.
        rows = self.table.get_children()

        if len(rows) > 200:

            self.table.delete(
                rows[0]
            )

        self.table.yview_moveto(1)