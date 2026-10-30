import tkinter as tk
from tkinter import ttk


class KaliTestPanel:
    """
    Controls for testing DNS traffic generated from the Kali VM.
    """

    def __init__(self, parent, start_callback, stop_callback):

        self.frame = tk.LabelFrame(
            parent,
            text="Kali Test",
            padx=10,
            pady=8
        )

        self.start_callback = start_callback
        self.stop_callback = stop_callback

        # -------------------------------------------------
        # Interface
        # -------------------------------------------------

        tk.Label(
            self.frame,
            text="TShark Interface:"
        ).pack(side="left", padx=(0, 5))

        self.interface_var = tk.StringVar(
            value="6"
        )

        self.interface_entry = ttk.Entry(
            self.frame,
            textvariable=self.interface_var,
            width=8
        )

        self.interface_entry.pack(
            side="left",
            padx=5
        )

        # -------------------------------------------------
        # Start button
        # -------------------------------------------------

        self.start_button = ttk.Button(
            self.frame,
            text="Start Kali Test",
            command=self.start_test
        )

        self.start_button.pack(
            side="left",
            padx=5
        )

        # -------------------------------------------------
        # Stop button
        # -------------------------------------------------

        self.stop_button = ttk.Button(
            self.frame,
            text="Stop Kali Test",
            command=self.stop_test,
            state="disabled"
        )

        self.stop_button.pack(
            side="left",
            padx=5
        )

    def get_interface(self):
        value = self.interface_var.get().strip()

        if not value:
            raise ValueError(
                "Kali test interface cannot be empty."
            )

        try:
            interface = int(value)
        except ValueError:
            raise ValueError(
                "Kali test interface must be a number."
            )

        if interface <= 0:
            raise ValueError(
                "Kali test interface must be positive."
            )

        return interface

    def start_test(self):
        self.start_callback(
            self.get_interface()
        )

    def stop_test(self):
        self.stop_callback()

    def set_running(self):
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
        self.start_button.config(
            state="normal"
        )

        self.stop_button.config(
            state="disabled"
        )

        self.interface_entry.config(
            state="normal"
        )