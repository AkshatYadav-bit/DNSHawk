from datetime import timedelta


class DNSWindow:
    """
    Represents DNS activity for one source host, one domain,
    and one fixed time window.
    """

    def __init__(
        self,
        src_ip,
        domain,
        start_time,
        window_size_seconds,
        events=None
    ):
        self.src_ip = src_ip
        self.domain = domain

        self.start_time = start_time

        self.window_size_seconds = window_size_seconds

        self.end_time = (
            start_time
            + timedelta(seconds=window_size_seconds)
        )

        self.events = events if events is not None else []

    # ---------------------------------------------------------
    # Event management
    # ---------------------------------------------------------

    def add_event(self, event):
        self.events.append(event)

    # ---------------------------------------------------------
    # Basic counts
    # ---------------------------------------------------------

    @property
    def event_count(self):
        return len(self.events)

    @property
    def query_count(self):
        return len(self.events)

    # ---------------------------------------------------------
    # Unique queries
    # ---------------------------------------------------------

    @property
    def unique_queries(self):
        return {
            event.query
            for event in self.events
        }

    @property
    def unique_query_count(self):
        return len(self.unique_queries)

    # ---------------------------------------------------------
    # Unique subdomains
    # ---------------------------------------------------------

    @property
    def unique_subdomains(self):
        return {
            event.subdomain
            for event in self.events
            if event.subdomain
        }

    @property
    def unique_subdomain_count(self):
        return len(self.unique_subdomains)

    # ---------------------------------------------------------
    # NXDOMAIN
    # ---------------------------------------------------------

    @property
    def nxdomain_count(self):
        return sum(
            1
            for event in self.events
            if event.is_nxdomain
        )

    @property
    def nxdomain_rate(self):
        if self.event_count == 0:
            return 0.0

        return self.nxdomain_count / self.event_count

    # ---------------------------------------------------------
    # Query rate
    # ---------------------------------------------------------

    @property
    def queries_per_second(self):
        if self.window_size_seconds <= 0:
            return 0.0

        return self.query_count / self.window_size_seconds

    # ---------------------------------------------------------
    # Query lengths
    # ---------------------------------------------------------

    @property
    def query_lengths(self):
        return [
            event.query_length
            for event in self.events
            if event.query_length is not None
        ]

    # ---------------------------------------------------------
    # Packet lengths
    # ---------------------------------------------------------

    @property
    def packet_lengths(self):
        return [
            event.packet_length
            for event in self.events
            if event.packet_length is not None
        ]

    # ---------------------------------------------------------
    # Response lengths
    # ---------------------------------------------------------

    @property
    def response_lengths(self):
        return [
            event.response_length
            for event in self.events
            if event.response_length is not None
        ]

    # ---------------------------------------------------------
    # Representation
    # ---------------------------------------------------------

    def __repr__(self):
        return (
            "DNSWindow("
            f"src_ip={self.src_ip!r}, "
            f"domain={self.domain!r}, "
            f"start_time={self.start_time!r}, "
            f"end_time={self.end_time!r}, "
            f"event_count={self.event_count}"
            ")"
        )