
"""Utilities for filtering security events and findings by severity.

Filtering creates new lists and does not modify the original evidence.
"""

VALID_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
)

ALL_SEVERITIES = "all"


def validate_severity_filter(severity: str) -> str:
    """Validate and normalize a severity filter."""

    if not isinstance(severity, str):
        raise ValueError("Severity filter must be a string.")

    normalized = severity.strip().lower()

    if normalized == ALL_SEVERITIES:
        return normalized

    if normalized not in VALID_SEVERITIES:
        allowed = ", ".join((ALL_SEVERITIES, *VALID_SEVERITIES))
        raise ValueError(
            f"Invalid severity filter. Choose one of: {allowed}."
        )

    return normalized


def filter_by_severity(
    items: list,
    severity: str = ALL_SEVERITIES,
) -> list:
    """Return items matching a severity without modifying the input."""

    if not isinstance(items, list):
        raise TypeError("items must be a list.")

    selected_severity = validate_severity_filter(severity)

    if selected_severity == ALL_SEVERITIES:
        return list(items)

    return [
        item
        for item in items
        if isinstance(item, dict)
        and isinstance(item.get("severity"), str)
        and item["severity"].strip().lower() == selected_severity
    ]


def filter_events_by_severity(
    events: list,
    severity: str = ALL_SEVERITIES,
) -> list:
    """Filter security events by their assigned severity."""

    return filter_by_severity(events, severity)


def filter_findings_by_severity(
    findings: list,
    severity: str = ALL_SEVERITIES,
) -> list:
    """Filter security findings by their assigned severity."""

    return filter_by_severity(findings, severity)
