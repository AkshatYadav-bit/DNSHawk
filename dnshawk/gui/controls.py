from tkinter import ttk


class ControlPanel:
    """
    Capture control panel.

    Handles:
    - Network interface input
    - Start button
    - Stop button
    """

    def __init__(
        self,
        parent,
        start_callback,
        stop_callback
    ):

        self.frame = ttk.Frame(
            parent,
            padding=(10, 0, 10, 10)
        )

        self.frame.pack(
            fill="x"
        )

        ttk.Label(
            self.frame,
            text="Interface:"
        ).pack(
            side="left"
        )

        self.interface_entry = ttk.Entry(
            self.frame,
            width=8
        )

        self.interface_entry.insert(
            0,
            "5"
        )

        self.interface_entry.pack(
            side="left",
            padx=(5, 10)
        )

        self.start_button = ttk.Button(
            self.frame,
            text="Start Capture",
            command=start_callback
        )

        self.start_button.pack(
            side="left",
            padx=5
        )

        self.stop_button = ttk.Button(
            self.frame,
            text="Stop Capture",
            command=stop_callback,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=5
        )

    def get_interface(self):
        """
        Return selected TShark interface as integer.
        """

        return int(
            self.interface_entry
            .get()
            .strip()
        )

    def set_running(self):
        """
        Update controls when capture starts.
        """

        self.start_button.config(
            state="disabled"
        )

        self.stop_button.config(
            state="normal"
        )

        self.interface_entry.config(
            state="disabled"
        )

    def set_stopped(self):
        """
        Update controls when capture stops.
        """

        self.start_button.config(
            state="normal"
        )

        self.stop_button.config(
            state="disabled"
        )

        self.interface_entry.config(
            state="normal"
        )