
import platform

from threatlens_ai.directory_integrity import (
    compare_directory_with_baseline,
    save_directory_baseline,
)
from threatlens_ai.directory_report import (
    export_directory_integrity_report,
    generate_directory_integrity_report,
)
from threatlens_ai.file_integrity import save_baseline
from threatlens_ai.integrity_report import (
    export_integrity_report,
    generate_integrity_report,
)
from threatlens_ai.log_report import (
    export_log_report,
    generate_log_report,
)


def main():
    """Run the ThreatLens AI command-line interface."""

    print("=" * 45)
    print("          ThreatLens AI")
    print("      Cybersecurity Utility Toolkit")
    print("=" * 45)
    print(f"Operating system: {platform.system()}")

    while True:
        print("\nChoose an option:")
        print("1. Save file integrity baseline")
        print("2. Generate file integrity report")
        print("3. Export integrity report to JSON")
        print("4. Exit")
        print("5. Save directory integrity baseline")
        print("6. Compare directory against baseline")
        print("7. Generate directory integrity report")
        print("8. Export directory integrity report to JSON")
        print("9. Analyze a security log file")
        print("10. Export security log analysis report to JSON")

        choice = input("\nEnter your choice (1-10): ").strip()

        try:
            if choice == "1":
                file_path = input("Enter file path: ").strip()
                baseline_path = input(
                    "Enter baseline path (default: baseline.json): "
                ).strip() or "baseline.json"

                file_hash = save_baseline(file_path, baseline_path)

                print("\nFile baseline saved successfully.")
                print(f"SHA-256: {file_hash}")

            elif choice == "2":
                file_path = input("Enter file path: ").strip()
                baseline_path = input(
                    "Enter baseline path (default: baseline.json): "
                ).strip() or "baseline.json"

                report = generate_integrity_report(
                    file_path,
                    baseline_path,
                )

                print("\nFile Integrity Report")
                print("-" * 30)

                for key, value in report.items():
                    print(f"{key}: {value}")

            elif choice == "3":
                file_path = input("Enter file path: ").strip()
                baseline_path = input(
                    "Enter baseline path (default: baseline.json): "
                ).strip() or "baseline.json"
                output_path = input(
                    "Enter report output path "
                    "(default: integrity_report.json): "
                ).strip() or "integrity_report.json"

                report = generate_integrity_report(
                    file_path,
                    baseline_path,
                )
                saved_path = export_integrity_report(
                    report,
                    output_path,
                )

                print("\nIntegrity report exported successfully.")
                print(f"Report saved to: {saved_path}")

            elif choice == "4":
                print("Thank you for using ThreatLens AI.")
                break

            elif choice == "5":
                directory_path = input(
                    "Enter directory path to monitor: "
                ).strip()
                baseline_path = input(
                    "Enter baseline output path "
                    "(default: directory_baseline.json): "
                ).strip() or "directory_baseline.json"

                hashes = save_directory_baseline(
                    directory_path,
                    baseline_path,
                )

                print("\nDirectory baseline saved successfully.")
                print(f"Files scanned: {len(hashes)}")
                print(f"Baseline saved to: {baseline_path}")

            elif choice == "6":
                directory_path = input(
                    "Enter directory path to compare: "
                ).strip()
                baseline_path = input(
                    "Enter baseline path "
                    "(default: directory_baseline.json): "
                ).strip() or "directory_baseline.json"

                changes = compare_directory_with_baseline(
                    directory_path,
                    baseline_path,
                )

                print("\nDirectory Integrity Results")
                print("=" * 35)

                for change_type in ("added", "modified", "deleted"):
                    files = changes[change_type]
                    print(f"\n{change_type.upper()} ({len(files)}):")

                    if files:
                        for file_path in files:
                            print(f"  - {file_path}")
                    else:
                        print("  None")

                total_changes = sum(
                    len(files) for files in changes.values()
                )

                if total_changes == 0:
                    print("\nNo changes detected.")
                else:
                    print(f"\nTotal detected changes: {total_changes}")

            elif choice in ("7", "8"):
                directory_path = input(
                    "Enter directory path to report on: "
                ).strip()
                baseline_path = input(
                    "Enter baseline path "
                    "(default: directory_baseline.json): "
                ).strip() or "directory_baseline.json"

                report = generate_directory_integrity_report(
                    directory_path,
                    baseline_path,
                )

                if choice == "7":
                    print("\nDirectory Integrity Report")
                    print("=" * 35)
                    print(f"Directory: {report['directory_path']}")
                    print(
                        f"Checked at (UTC): "
                        f"{report['checked_at_utc']}"
                    )
                    print(f"Status: {report['status']}")
                    print(f"Total changes: {report['total_changes']}")
                    print("\nSummary:")

                    for change_type, count in report["summary"].items():
                        print(
                            f"  {change_type.capitalize()}: {count}"
                        )

                    for change_type, files in report["changes"].items():
                        print(f"\n{change_type.upper()}:")

                        if files:
                            for file_path in files:
                                print(f"  - {file_path}")
                        else:
                            print("  None")

                else:
                    output_path = input(
                        "Enter report output path "
                        "(default: directory_integrity_report.json): "
                    ).strip() or "directory_integrity_report.json"

                    saved_path = export_directory_integrity_report(
                        report,
                        output_path,
                    )

                    print("\nDirectory integrity report exported.")
                    print(f"Status: {report['status']}")
                    print(f"Total changes: {report['total_changes']}")
                    print(f"Report saved to: {saved_path}")

            elif choice in ("9", "10"):
                log_path = input(
                    "Enter security log file path: "
                ).strip()

                threshold_input = input(
                    "Failed-login alert threshold (default: 5): "
                ).strip()

                threshold = (
                    int(threshold_input)
                    if threshold_input
                    else 5
                )

                report = generate_log_report(
                    log_path,
                    failed_login_threshold=threshold,
                )

                if choice == "9":
                    print("\nSecurity Log Analysis Report")
                    print("=" * 35)
                    print(f"Log file: {report['file_path']}")
                    print(
                        f"Generated at (UTC): "
                        f"{report['generated_at_utc']}"
                    )

                    print("\nSummary:")
                    for key, value in report["summary"].items():
                        print(
                            f"  {key.replace('_', ' ').capitalize()}: "
                            f"{value}"
                        )

                    print("\nSource IP counts:")
                    if report["source_ip_counts"]:
                        for ip_address, count in (
                            report["source_ip_counts"].items()
                        ):
                            print(f"  {ip_address}: {count}")
                    else:
                        print(
                            "  No source IPs found in failed-login events."
                        )

                    print("\nRepeated Failed-Login Alerts:")
                    repeated_ips = report[
                        "repeated_failed_login_ips"
                    ]

                    if repeated_ips:
                        for finding in repeated_ips:
                            print(
                                f"  [{finding['severity'].upper()}] "
                                f"{finding['ip_address']}: "
                                f"{finding['failed_login_count']} "
                                "failed-login entries"
                            )
                    else:
                        print(
                            "  No IP addresses reached the configured "
                            "failed-login threshold."
                        )

                    print("\nSuspicious events:")
                    if report["suspicious_events"]:
                        for event in report["suspicious_events"]:
                            print(
                                f"  Line {event['line_number']}: "
                                f"{event['event_type']} - "
                                f"{event['message']}"
                            )
                    else:
                        print(
                            "  No matching failed-login events detected."
                        )

                    print(
                        "\nNote: These are rule-based indicators, "
                        "not proof of an attack."
                    )

                else:
                    output_path = input(
                        "Enter report output path "
                        "(default: security_log_report.json): "
                    ).strip() or "security_log_report.json"

                    saved_path = export_log_report(
                        report,
                        output_path,
                    )

                    print("\nSecurity log report exported successfully.")
                    print(
                        "Failed login events: "
                        f"{report['summary']['failed_login_count']}"
                    )
                    print(
                        "Repeated failed-login IPs: "
                        f"{report['summary']['repeated_failed_login_ip_count']}"
                    )
                    print(f"Report saved to: {saved_path}")

            else:
                print(
                    "Invalid choice. Please enter a number from 1 to 10."
                )

        except (OSError, ValueError, KeyError) as error:
            print(f"\nError: {error}")

        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")


if __name__ == "__main__":
    main()
