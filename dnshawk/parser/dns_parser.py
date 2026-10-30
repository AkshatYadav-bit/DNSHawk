from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from dnshawk.models.dns_event import DNSEvent


def normalize_packet_timestamp(packet):
    """
    Convert Scapy's packet timestamp into a standard datetime.

    Scapy commonly represents packet.time as an EDecimal.
    DNSEvent should not depend on Scapy-specific timestamp types.
    """

    return datetime.fromtimestamp(
        float(packet.time),
        tz=timezone.utc
    )


def parse_dns_packet(packet):
    """
    Convert a Scapy DNS query packet into a normalized DNSEvent.

    Returns:
        DNSEvent: if the packet contains a DNS query.
        None: otherwise.
    """

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    # We currently process DNS query packets.
    if not dns.qd:
        return None

    query_record = dns.qd

    if not query_record.haslayer(DNSQR):
        return None

    # IPv4
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    # IPv6
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    else:
        return None

    # DNS query name
    query = query_record.qname

    if isinstance(query, bytes):
        query = query.decode(
            "utf-8",
            errors="replace"
        )

    # DNS query type
    qtype = query_record.qtype

    # DNS response code
    rcode = dns.rcode

    # Complete packet size
    packet_length = len(packet)

    # Response correlation will be implemented later.
    response_length = 0

    return DNSEvent(
        timestamp=normalize_packet_timestamp(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        query=query,
        qtype=qtype,
        packet_length=packet_length,
        response_length=response_length,
        rcode=rcode
    )


def parse_tshark_line(line):
    """
    Convert one live TShark field-output line into a normalized DNSEvent.

    Expected TShark format:

        timestamp|ipv4_src|ipv6_src|ipv4_dst|ipv6_dst|
        query|qtype|response_flag|rcode|packet_length

    Returns:
        DNSEvent: if the line represents a DNS query.
        None: otherwise.
    """

    if not line:
        return None

    fields = line.strip().split("|")

    if len(fields) != 10:
        return None

    (
        timestamp,
        ipv4_src,
        ipv6_src,
        ipv4_dst,
        ipv6_dst,
        query,
        qtype,
        response_flag,
        rcode,
        packet_length
    ) = fields

    # We currently process DNS query packets only.
    if response_flag.lower() == "true":
        return None

    src_ip = ipv4_src or ipv6_src
    dst_ip = ipv4_dst or ipv6_dst

    if not src_ip or not dst_ip:
        return None

    if not query:
        return None

    try:
        timestamp = datetime.fromtimestamp(
            float(timestamp),
            tz=timezone.utc
        )

        packet_length = int(packet_length)

        if rcode:
            rcode = int(rcode)
        else:
            rcode = 0

    except (ValueError, TypeError):
        return None

    return DNSEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        query=query,
        qtype=qtype,
        packet_length=packet_length,
        response_length=0,
        rcode=rcode
    )