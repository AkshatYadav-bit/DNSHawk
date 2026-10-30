import tkinter as tk
from tkinter import ttk


class HeaderPanel:
    """
    Header containing the application title
    and capture status.
    """

    def __init__(self, parent):

        self.frame = ttk.Frame(
            parent,
            padding=10
        )

        self.frame.pack(
            fill="x"
        )

        self.title_label = ttk.Label(
            self.frame,
            text="DNSHawk - DNS Traffic Monitor",
            font=("Segoe UI", 18, "bold")
        )

        self.title_label.pack(
            side="left"
        )

        self.status_label = ttk.Label(
            self.frame,
            text="● STOPPED",
            foreground="red",
            font=("Segoe UI", 11, "bold")
        )

        self.status_label.pack(
            side="right"
        )

    def set_status(self, text, color):
        """
        Update capture status.
        """

        self.status_label.config(
            text=text,
            foreground=color
        )