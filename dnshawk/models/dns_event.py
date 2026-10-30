from datetime import datetime
import ipaddress


class DNSEvent:

    def __init__(
        self,
        timestamp,
        src_ip,
        dst_ip,
        query,
        qtype,
        packet_length,
        response_length=None,
        rcode=None
    ):
        self.timestamp = self.normalize_timestamp(timestamp)

        self.src_ip = self.normalize_ip(src_ip)
        self.dst_ip = self.normalize_ip(dst_ip)

        self.query = self.normalize_query(query)

        self.domain = self.get_domain(self.query)
        self.subdomain = self.get_subdomain(self.query)

        self.qtype = self.normalize_qtype(qtype)

        self.query_length = len(self.query)

        self.packet_length = self.normalize_length(packet_length)
        self.response_length = self.normalize_length(response_length)

        self.rcode = self.normalize_rcode(rcode)

        self.is_nxdomain = self.rcode == 3

    # ---------------------------------------------------------
    # Timestamp
    # ---------------------------------------------------------

    @staticmethod
    def normalize_timestamp(timestamp):
        """
        Convert timestamp to datetime.

        Supports:
        - datetime objects
        - ISO-8601 strings
        """

        if isinstance(timestamp, datetime):
            return timestamp

        if isinstance(timestamp, str):
            timestamp = timestamp.strip()

            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as e:
                raise ValueError(
                    f"Invalid DNS timestamp: {timestamp}"
                ) from e

        raise TypeError(
            f"Timestamp must be datetime or str, got {type(timestamp).__name__}"
        )

    # ---------------------------------------------------------
    # IP addresses
    # ---------------------------------------------------------

    @staticmethod
    def normalize_ip(ip):
        """
        Validate and normalize IPv4/IPv6 address.
        """

        if ip is None:
            return None

        try:
            return str(ipaddress.ip_address(str(ip).strip()))
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip}") from e

    # ---------------------------------------------------------
    # DNS query
    # ---------------------------------------------------------

    @staticmethod
    def normalize_query(query):
        """
        Normalize a DNS query name.

        Removes surrounding whitespace and trailing/leading dots.
        Converts DNS names to lowercase.
        """

        if query is None:
            return ""

        query = str(query).strip()

        return query.strip(".").lower()

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    @staticmethod
    def get_domain(query):
        """
        Extract the registered domain.

        NOTE:
        This implementation currently assumes the final two labels
        represent the registered domain.

        A public-suffix-aware implementation should be introduced
        before production/research evaluation.
        """

        if not query:
            return ""

        labels = query.split(".")

        if len(labels) < 2:
            return query

        return ".".join(labels[-2:])

    # ---------------------------------------------------------
    # Subdomain
    # ---------------------------------------------------------

    @staticmethod
    def get_subdomain(query):
        """
        Extract everything preceding the domain.
        """

        if not query:
            return ""

        labels = query.split(".")

        if len(labels) <= 2:
            return ""

        return ".".join(labels[:-2])

    # ---------------------------------------------------------
    # Query type
    # ---------------------------------------------------------

    @staticmethod
    def normalize_qtype(qtype):
        if qtype is None:
            return None

        return str(qtype).strip().upper()

    # ---------------------------------------------------------
    # Packet / response length
    # ---------------------------------------------------------

    @staticmethod
    def normalize_length(value):
        if value is None:
            return None

        try:
            return int(value)
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"Invalid length value: {value}"
            ) from e

    # ---------------------------------------------------------
    # DNS RCODE
    # ---------------------------------------------------------

    @staticmethod
    def normalize_rcode(rcode):
        """
        Normalize DNS response code to integer.

        Examples:
            0       -> 0
            "0"     -> 0
            "NOERROR" -> 0
            3       -> 3
            "3"     -> 3
            "NXDOMAIN" -> 3
        """

        if rcode is None:
            return None

        if isinstance(rcode, int):
            return rcode

        if isinstance(rcode, str):

            value = rcode.strip().upper()

            rcode_map = {
                "NOERROR": 0,
                "FORMERR": 1,
                "SERVFAIL": 2,
                "NXDOMAIN": 3,
                "NOTIMP": 4,
                "REFUSED": 5,
            }

            if value in rcode_map:
                return rcode_map[value]

            try:
                return int(value)
            except ValueError:
                raise ValueError(
                    f"Unknown DNS RCODE: {rcode}"
                )

        raise TypeError(
            f"RCODE must be int, str, or None, got {type(rcode).__name__}"
        )

    # ---------------------------------------------------------
    # Representation
    # ---------------------------------------------------------

    def __repr__(self):
        return (
            "DNSEvent("
            f"timestamp={self.timestamp!r}, "
            f"src_ip={self.src_ip!r}, "
            f"dst_ip={self.dst_ip!r}, "
            f"query={self.query!r}, "
            f"domain={self.domain!r}, "
            f"subdomain={self.subdomain!r}, "
            f"qtype={self.qtype!r}, "
            f"query_length={self.query_length}, "
            f"packet_length={self.packet_length}, "
            f"response_length={self.response_length}, "
            f"rcode={self.rcode}, "
            f"is_nxdomain={self.is_nxdomain}"
            ")"
        )