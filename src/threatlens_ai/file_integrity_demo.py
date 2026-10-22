
from pathlib import Path

from threatlens_ai.file_integrity import calculate_sha256, save_baseline, check_integrity


sample_file = Path("sample.txt")
baseline_file = "baseline.json"

try:
    if not sample_file.is_file():
        print("Error: sample.txt was not found.")
    else:
        print("Current SHA-256:", calculate_sha256(str(sample_file)))

        choice = input(
            "\nChoose an action:\n"
            "1. Save baseline\n"
            "2. Check integrity\n"
            "Enter 1 or 2: "
        ).strip()

        if choice == "1":
            saved_hash = save_baseline(str(sample_file), baseline_file)
            print("\nBaseline saved successfully.")
            print("Saved SHA-256:", saved_hash)

        elif choice == "2":
            result = check_integrity(str(sample_file), baseline_file)
            print("\n" + result)

        else:
            print("Invalid choice. Enter 1 or 2.")

except (OSError, ValueError, KeyError) as error:
    print(f"Error: {error}")
