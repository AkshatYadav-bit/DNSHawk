from datetime import datetime

from dnshawk.models.dns_window import DNSWindow


class WindowManager:
    """
    Groups DNS events into fixed-duration windows.

    Current grouping key:

        source IP + domain + time window

    Current default:

        60 seconds
    """

    def __init__(self, window_size_seconds=60):

        if not isinstance(window_size_seconds, int):
            raise TypeError(
                "window_size_seconds must be an integer"
            )

        if window_size_seconds <= 0:
            raise ValueError(
                "window_size_seconds must be greater than zero"
            )

        self.window_size_seconds = window_size_seconds

    # ---------------------------------------------------------
    # Window boundary
    # ---------------------------------------------------------

    def get_window_start(self, timestamp):
        """
        Return the beginning of the fixed time window.

        Example with a 60-second window:

            10:00:05 -> 10:00:00
            10:00:45 -> 10:00:00
            10:01:05 -> 10:01:00
        """

        epoch = timestamp.timestamp()

        window_start_epoch = (
            epoch
            - (epoch % self.window_size_seconds)
        )

        return datetime.fromtimestamp(
            window_start_epoch,
            tz=timestamp.tzinfo
        )

    # ---------------------------------------------------------
    # Aggregation
    # ---------------------------------------------------------

    def aggregate(self, events):
        """
        Group events by:

            source IP
            domain
            window start
        """

        windows = {}

        for event in events:

            window_start = self.get_window_start(
                event.timestamp
            )

            key = (
                event.src_ip,
                event.domain,
                window_start
            )

            if key not in windows:

                windows[key] = DNSWindow(
                    src_ip=event.src_ip,
                    domain=event.domain,
                    start_time=window_start,
                    window_size_seconds=self.window_size_seconds
                )

            windows[key].add_event(event)

        return sorted(
            windows.values(),
            key=lambda window: (
                window.start_time,
                window.src_ip,
                window.domain
            )
        )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    def summarize(self, windows):

        total_events = sum(
            window.event_count
            for window in windows
        )

        return {
            "window_size_seconds": self.window_size_seconds,
            "window_count": len(windows),
            "event_count": total_events
        }