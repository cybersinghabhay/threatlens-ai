
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from .ip_intelligence import classify_ip_address


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

# Match IPv4- and IPv6-shaped candidates.
# Candidates are validated separately using ipaddress-based classification.
IP_ADDRESS_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.:])"
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]+"
    r")"
    r"(?![A-Za-z0-9_.:])"
)

# Recognize YYYY-MM-DD HH:MM:SS timestamps.
TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b"
)

# Initial rule-based severity for individual log events.
EVENT_SEVERITY = {
    "failed_login": "informational",
    "successful_login": "informational",
    "warning": "low",
    "error": "medium",
    "critical": "critical",
}


def get_event_severity(event_type: str) -> str:
    """Return the configured severity for an event type."""

    return EVENT_SEVERITY.get(event_type, "unknown")


def extract_ip_addresses(log_line: str) -> list:
    """Extract and validate unique IPv4 and IPv6 addresses."""

    extracted_ips = []

    for candidate in IP_ADDRESS_PATTERN.findall(log_line):
        result = classify_ip_address(candidate)

        if result["valid"] and candidate not in extracted_ips:
            extracted_ips.append(candidate)

    return extracted_ips


def enrich_event_with_ip(event: dict, log_line: str) -> dict:
    """Add IP address and IP intelligence information to an event."""

    ip_addresses = extract_ip_addresses(log_line)

    source_ip = ip_addresses[0] if ip_addresses else None

    event["source_ip"] = source_ip
    event["ip_intelligence"] = (
        classify_ip_address(source_ip)
        if source_ip is not None
        else None
    )

    return event


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
    total_lines = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:
        for line_number, line in enumerate(log_file, start=1):
            total_lines = line_number
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

                event = {
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "failed_login",
                    "severity": get_event_severity("failed_login"),
                    "message": text,
                }

                suspicious_events.append(
                    enrich_event_with_ip(event, text)
                )

                # Count IP addresses only in failed-login events.
                for ip_address in extract_ip_addresses(text):
                    source_ip_counts[ip_address] += 1

            # Check whether the line indicates a successful login.
            is_successful_login = any(
                pattern.search(text)
                for pattern in SUCCESSFUL_LOGIN_PATTERNS
            )

            if is_successful_login:
                event = {
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "successful_login",
                    "severity": get_event_severity("successful_login"),
                    "message": text,
                }

                suspicious_events.append(
                    enrich_event_with_ip(event, text)
                )

            # Detect and record warning events.
            if re.search(
                r"\bwarning\b|\bwarn\b",
                text,
                re.IGNORECASE,
            ):
                warning_count += 1

                event = {
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "warning",
                    "severity": get_event_severity("warning"),
                    "message": text,
                }

                suspicious_events.append(
                    enrich_event_with_ip(event, text)
                )

            # Detect and record error and critical events.
            if re.search(r"\berror\b", text, re.IGNORECASE):
                error_count += 1

                event = {
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "error",
                    "severity": get_event_severity("error"),
                    "message": text,
                }

                suspicious_events.append(
                    enrich_event_with_ip(event, text)
                )

            elif re.search(r"\bcritical\b", text, re.IGNORECASE):
                error_count += 1

                event = {
                    "timestamp": timestamp,
                    "line_number": line_number,
                    "event_type": "critical",
                    "severity": get_event_severity("critical"),
                    "message": text,
                }

                suspicious_events.append(
                    enrich_event_with_ip(event, text)
                )

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
        "total_lines": total_lines,
        "failed_login_count": failed_login_count,
        "warning_count": warning_count,
        "error_count": error_count,
        "source_ip_counts": dict(source_ip_counts.most_common()),
        "suspicious_events": suspicious_events,
        "failed_login_threshold": failed_login_threshold,
        "repeated_failed_login_ips": repeated_failed_login_ips,
    }
