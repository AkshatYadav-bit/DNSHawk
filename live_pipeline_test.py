from dnshawk.collector.tshark_capture import TSharkCapture
from dnshawk.parser.dns_parser import parse_tshark_line
from dnshawk.aggregation.window import WindowManager
from dnshawk.features.feature_engine import FeatureEngine
from dnshawk.detection.rule_detector import RuleDetector


INTERFACE = 6
WINDOW_SIZE = 60
EVENT_LIMIT = 20


def main():
    print("=" * 70)
    print("DNSHawk Live Pipeline Test")
    print("=" * 70)

    capture = TSharkCapture(INTERFACE)
    window_manager = WindowManager(WINDOW_SIZE)
    feature_engine = FeatureEngine()
    rule_detector = RuleDetector()

    events = []

    print("\n[1] Starting live TShark capture...")
    stream = capture.start()

    try:
        print("[2] Waiting for DNS events...")
        print("    Generate DNS traffic from Kali if necessary.")
        print()

        while len(events) < EVENT_LIMIT:
            line = next(stream)

            event = parse_tshark_line(line)

            if event is None:
                continue

            events.append(event)

            print(
                f"Event {len(events):02d}: "
                f"{event.src_ip} -> {event.query} "
                f"(qtype={event.qtype})"
            )

    except KeyboardInterrupt:
        print("\nCapture interrupted.")

    finally:
        capture.stop()

    if not events:
        print("\nNo DNS events captured.")
        return

    print("\n" + "=" * 70)
    print("WINDOW AGGREGATION")
    print("=" * 70)

    windows = window_manager.aggregate(events)

    print(f"Events captured : {len(events)}")
    print(f"Windows created : {len(windows)}")

    for index, window in enumerate(windows, start=1):

        print("\n" + "-" * 70)
        print(f"WINDOW {index}")
        print("-" * 70)

        print(f"Source IP       : {window.src_ip}")
        print(f"Domain          : {window.domain}")
        print(f"Start           : {window.start_time}")
        print(f"End             : {window.end_time}")
        print(f"Query count     : {window.query_count}")
        print(f"Unique queries  : {window.unique_query_count}")
        print(f"Unique subdoms  : {window.unique_subdomain_count}")
        print(f"NXDOMAIN rate   : {window.nxdomain_rate:.4f}")

        print("\n[FEATURES]")

        features = feature_engine.extract(window)

        for name, value in features.items():
            print(f"{name:25s}: {value}")

        print("\n[RULE DETECTION]")

        detection = rule_detector.assess(features)

        print(
            f"Minimum evidence : "
            f"{detection['minimum_evidence_met']}"
        )

        print(
            f"Score            : "
            f"{detection['score']:.2f} / "
            f"{detection['max_score']:.2f}"
        )

        print(
            f"Normalized score : "
            f"{detection['normalized_score']:.2f}"
        )

        print(
            f"Triggered rules  : "
            f"{detection['triggered_rules']}"
        )

        print("\nRule details:")

        for rule_name, result in detection["rule_results"].items():

            status = "TRIGGERED" if result["triggered"] else "not triggered"

            print(
                f"  {rule_name:30s} "
                f"{status:15s} "
                f"value={result['value']}"
            )

    print("\n" + "=" * 70)
    print("LIVE PIPELINE TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()