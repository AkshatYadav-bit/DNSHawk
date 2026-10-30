from datetime import datetime, timedelta

from dnshawk.models.dns_event import DNSEvent
from dnshawk.aggregation.window import WindowManager


def create_event(
    timestamp,
    query,
    src_ip="192.168.1.10",
    nxdomain=False
):

    rcode = 3 if nxdomain else 0

    return DNSEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        query=query,
        qtype="A",
        packet_length=100,
        response_length=120,
        rcode=rcode
    )


def test_same_window():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "abc.example.com"
        ),
        create_event(
            base_time + timedelta(seconds=10),
            "xyz.example.com"
        ),
        create_event(
            base_time + timedelta(seconds=20),
            "hello.example.com"
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    assert len(windows) == 1

    window = windows[0]

    assert window.src_ip == "192.168.1.10"
    assert window.domain == "example.com"

    assert window.event_count == 3
    assert window.unique_query_count == 3


def test_different_time_windows():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "abc.example.com"
        ),
        create_event(
            base_time + timedelta(seconds=70),
            "xyz.example.com"
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    assert len(windows) == 2


def test_different_hosts():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "abc.example.com",
            src_ip="192.168.1.10"
        ),
        create_event(
            base_time,
            "abc.example.com",
            src_ip="192.168.1.20"
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    assert len(windows) == 2


def test_different_domains():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "abc.example.com"
        ),
        create_event(
            base_time,
            "abc.google.com"
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    assert len(windows) == 2


def test_nxdomain_rate():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "abc.example.com",
            nxdomain=False
        ),
        create_event(
            base_time + timedelta(seconds=5),
            "xyz.example.com",
            nxdomain=True
        ),
        create_event(
            base_time + timedelta(seconds=10),
            "foo.example.com",
            nxdomain=True
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    assert len(windows) == 1

    window = windows[0]

    assert window.nxdomain_count == 2

    assert window.nxdomain_rate == 2 / 3


def test_query_rate():

    base_time = datetime(
        2026, 9, 30, 10, 0, 10
    )

    events = [
        create_event(
            base_time,
            "a.example.com"
        ),
        create_event(
            base_time + timedelta(seconds=10),
            "b.example.com"
        )
    ]

    manager = WindowManager(60)

    windows = manager.aggregate(events)

    window = windows[0]

    assert window.queries_per_second == 2 / 60