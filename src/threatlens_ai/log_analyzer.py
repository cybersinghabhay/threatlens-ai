
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


# Common log messages that may indicate failed authentication.
FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed password", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"failed login", re.IGNORECASE),
    re.compile(r"invalid user", re.IGNORECASE),
]
# Common log messages indicating successful authentication.
SUCCESSFUL_LOGIN_PATTERNS = [
    re.compile(r"\baccepted password for\b", re.IGNORECASE),
]

# Extract IPv4-style addresses from matching log lines.
IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Recognize YYYY-MM-DD HH:MM:SS timestamps.
TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b"
)


def extract_timestamp(log_line: str):
    """Extract and validate a timestamp from a log line."""

    match = TIMESTAMP_PATTERN.search(log_line)

    if match is None:
        return None

    timestamp_text = match.group()

    try:
        parsed_timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None

    return parsed_timestamp.isoformat()


def analyze_log_file(
    log_path: str,
    failed_login_threshold: int = 5,
) -> dict:
    """Analyze a text log file for suspicious patterns and repeated failed logins."""

    # Validate the failed-login detection threshold.
    # A threshold must be a positive integer; True/False are not accepted.
    if (
        not isinstance(failed_login_threshold, int)
        or isinstance(failed_login_threshold, bool)
        or failed_login_threshold < 1
    ):
        raise ValueError(
            "Failed login threshold must be a positive integer."
        )

    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Log file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Expected a file, not a directory: {path}"
        )

    failed_login_count = 0
    warning_count = 0
    error_count = 0

    source_ip_counts = Counter()
    suspicious_events = []

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:
        for line_number, line in enumerate(log_file, start=1):
            text = line.strip()

            # Skip empty lines.
            if not text:
                continue

            # Extract a timestamp from the log line.
            timestamp = extract_timestamp(text)

            # Check whether the line indicates a failed login.
            is_failed_login = any(
                pattern.search(text)
                for pattern in FAILED_LOGIN_PATTERNS
            )

            if is_failed_login:
                failed_login_count += 1

                suspicious_events.append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "failed_login",
                    "message": text,
                })

                # Count IP addresses found in failed-login lines.
                for ip_address in IP_ADDRESS_PATTERN.findall(text):
                    source_ip_counts[ip_address] += 1
                # Check whether the line indicates a successful login.
            is_successful_login = any(
                pattern.search(text)
                for pattern in SUCCESSFUL_LOGIN_PATTERNS
            )

            if is_successful_login:
                suspicious_events.append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "successful_login",
                    "message": text,
                })

            # Detect and record warning events.
            if re.search(
                r"\bwarning\b|\bwarn\b",
                text,
                re.IGNORECASE,
            ):
                warning_count += 1

                suspicious_events.append({
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "warning",
                    "message": text,
                })

            # Count errors and critical events.
            if re.search(
                r"\berror\b|\bcritical\b",
                text,
                re.IGNORECASE,
            ):
                error_count += 1

    # Detect IP addresses reaching the configured threshold.
    repeated_failed_login_ips = []

    for ip_address, count in source_ip_counts.most_common():
        if count >= failed_login_threshold:
            # Ten or more failed-login entries from an IP are high severity.
            severity = "high" if count >= 10 else "medium"

            repeated_failed_login_ips.append({
                "ip_address": ip_address,
                "failed_login_count": count,
                "severity": severity,
            })

    return {
        "file_path": str(path.resolve()),
        "total_lines": line_number if "line_number" in locals() else 0,
        "failed_login_count": failed_login_count,
        "warning_count": warning_count,
        "error_count": error_count,
        "source_ip_counts": dict(source_ip_counts.most_common()),
        "suspicious_events": suspicious_events,
        "failed_login_threshold": failed_login_threshold,
        "repeated_failed_login_ips": repeated_failed_login_ips,
    }
