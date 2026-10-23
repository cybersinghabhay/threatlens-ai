
"""
ThreatLens AI
A cross-platform cybersecurity analysis toolkit.
"""

import platform

from threatlens_ai.file_integrity import save_baseline
from threatlens_ai.integrity_report import generate_integrity_report


def main():
    """Display the startup information and main menu."""

    print("=" * 45)
    print("          ThreatLens AI")
    print("  AI-Powered Cybersecurity Toolkit")
    print("=" * 45)

    print(f"Operating System: {platform.system()}")
    print(f"Python Version: {platform.python_version()}")

    print("\nThreatLens AI has started successfully!")

    while True:
        print("\n" + "-" * 45)
        print(" MAIN MENU")
        print("-" * 45)
        print("1. Save file integrity baseline")
        print("2. Generate file integrity report")
        print("3. Exit")

        choice = input("\nEnter your choice (1-3): ").strip()

        if choice == "1":
            file_path = input("Enter the file path: ").strip().strip('"')

            try:
                saved_hash = save_baseline(file_path)
                print("\nBaseline saved successfully!")
                print(f"SHA-256: {saved_hash}")

            except (OSError, ValueError) as error:
                print(f"\nError: {error}")

        elif choice == "2":
            file_path = input("Enter the file path: ").strip().strip('"')

            try:
                report = generate_integrity_report(file_path)

                print("\n" + "-" * 45)
                print(" FILE INTEGRITY REPORT")
                print("-" * 45)
                print(f"File: {report['file_path']}")
                print(f"Expected SHA-256: {report['expected_sha256']}")
                print(f"Current SHA-256:  {report['current_sha256']}")
                print(f"Status: {report['status']}")
                print(f"Checked at (UTC): {report['checked_at_utc']}")

            except (OSError, ValueError, KeyError) as error:
                print(f"\nError: {error}")

        elif choice == "3":
            print("\nThank you for using ThreatLens AI!")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
