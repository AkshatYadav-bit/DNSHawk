import math
from statistics import mean, pstdev


class FeatureEngine:
    """
    Extract analytical features from a DNSWindow.

    The engine is intentionally independent of the GUI and
    detection layer.
    """

    # ---------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------

    def extract(self, window):
        """
        Extract DNS behavioral, lexical, and subdomain features.

        Returns:
            dict: feature name -> numeric value
        """

        return {
            "query_count": window.query_count,
            "unique_query_count": window.unique_query_count,
            "unique_query_ratio": self.unique_query_ratio(window),
            "queries_per_second": window.queries_per_second,

            "avg_query_length": self.average(
                window.query_lengths
            ),

            "max_query_length": self.maximum(
                window.query_lengths
            ),

            "entropy": self.average_query_entropy(window),

            # -------------------------------------------------
            # NEW: Subdomain features
            # -------------------------------------------------

            "avg_subdomain_length":
                self.average_subdomain_length(window),

            "max_subdomain_length":
                self.maximum_subdomain_length(window),

            "avg_subdomain_entropy":
                self.average_subdomain_entropy(window),

            "max_subdomain_entropy":
                self.maximum_subdomain_entropy(window),

            "unique_subdomain_count":
                window.unique_subdomain_count,

            "unique_subdomain_ratio":
                self.unique_subdomain_ratio(window),

            # -------------------------------------------------
            # Existing features
            # -------------------------------------------------

            "nxdomain_rate": window.nxdomain_rate,

            "mean_interarrival": self.mean_interarrival(window),
            "std_interarrival": self.std_interarrival(window),

            "avg_packet_length": self.average(
                window.packet_lengths
            ),

            "max_packet_length": self.maximum(
                window.packet_lengths
            ),

            "avg_response_length": self.average(
                window.response_lengths
            ),
        }

    # ---------------------------------------------------------
    # Basic statistics
    # ---------------------------------------------------------

    @staticmethod
    def average(values):
        if not values:
            return 0.0

        return float(mean(values))

    @staticmethod
    def maximum(values):
        if not values:
            return 0.0

        return float(max(values))

    # ---------------------------------------------------------
    # Behavioral features
    # ---------------------------------------------------------

    @staticmethod
    def unique_query_ratio(window):
        if window.query_count == 0:
            return 0.0

        return (
            window.unique_query_count
            / window.query_count
        )

    # ---------------------------------------------------------
    # Subdomain features
    # ---------------------------------------------------------

    @staticmethod
    def subdomain_lengths(window):
        """
        Return the lengths of all non-empty subdomains
        present in the DNS window.
        """

        return [
            len(event.subdomain)
            for event in window.events
            if event.subdomain
        ]

    def average_subdomain_length(self, window):
        """
        Calculate the average subdomain length.
        """

        return self.average(
            self.subdomain_lengths(window)
        )

    def maximum_subdomain_length(self, window):
        """
        Calculate the maximum subdomain length.
        """

        return self.maximum(
            self.subdomain_lengths(window)
        )

    # ---------------------------------------------------------
    # Subdomain entropy
    # ---------------------------------------------------------

    def subdomain_entropies(self, window):
        """
        Calculate Shannon entropy for each non-empty
        subdomain in the window.
        """

        return [
            self.shannon_entropy(event.subdomain)
            for event in window.events
            if event.subdomain
        ]

    def average_subdomain_entropy(self, window):
        """
        Calculate the mean Shannon entropy across
        subdomains in the window.
        """

        return self.average(
            self.subdomain_entropies(window)
        )

    def maximum_subdomain_entropy(self, window):
        """
        Calculate the maximum Shannon entropy
        observed among subdomains in the window.
        """

        return self.maximum(
            self.subdomain_entropies(window)
        )

    # ---------------------------------------------------------
    # Unique subdomain ratio
    # ---------------------------------------------------------

    @staticmethod
    def unique_subdomain_ratio(window):
        """
        Calculate the ratio of unique subdomains
        to all non-empty subdomain observations.
        """

        subdomain_events = [
            event
            for event in window.events
            if event.subdomain
        ]

        if not subdomain_events:
            return 0.0

        return (
            window.unique_subdomain_count
            / len(subdomain_events)
        )

    # ---------------------------------------------------------
    # Entropy
    # ---------------------------------------------------------

    @staticmethod
    def shannon_entropy(value):
        """
        Calculate Shannon entropy of a string.
        """

        if not value:
            return 0.0

        counts = {}

        for character in value:
            counts[character] = (
                counts.get(character, 0) + 1
            )

        length = len(value)
        entropy = 0.0

        for count in counts.values():
            probability = count / length

            entropy -= (
                probability
                * math.log2(probability)
            )

        return entropy

    def average_query_entropy(self, window):
        """
        Calculate the mean Shannon entropy across
        DNS queries in the window.
        """

        entropies = [
            self.shannon_entropy(event.query)
            for event in window.events
            if event.query
        ]

        return self.average(entropies)

    # ---------------------------------------------------------
    # Temporal features
    # ---------------------------------------------------------

    @staticmethod
    def interarrival_times(window):
        """
        Return inter-arrival times between consecutive
        DNS events in seconds.
        """

        if len(window.events) < 2:
            return []

        timestamps = sorted(
            event.timestamp
            for event in window.events
        )

        return [
            (
                timestamps[index]
                - timestamps[index - 1]
            ).total_seconds()

            for index in range(1, len(timestamps))
        ]

    def mean_interarrival(self, window):
        values = self.interarrival_times(window)

        return self.average(values)

    def std_interarrival(self, window):
        values = self.interarrival_times(window)

        if len(values) < 2:
            return 0.0

        return float(pstdev(values))