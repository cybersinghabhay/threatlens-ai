
"""Explain security findings using deterministic rules.

This module explains findings; it does not detect threats or
replace the existing detection engine.
"""


def explain_finding(finding: dict) -> dict:
    """Return an explanation and recommended action for a finding."""

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary")

    event_type = finding.get("event_type", "")
    severity = finding.get("severity", "unknown")

    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string")

    if not isinstance(severity, str):
        raise ValueError("severity must be a string")

    if event_type == "repeated_failed_login":
        explanation = (
            "Multiple failed login attempts were detected for "
            "the same source. This may indicate a brute-force "
            "attempt, but it could also result from a user "
            "entering an incorrect password repeatedly."
        )
        recommended_action = (
            "Review the authentication logs, verify whether the "
            "activity is expected, and check for successful "
            "logins from the same source."
        )

    elif event_type == "file_modified":
        explanation = (
            "The file differs from its saved integrity baseline. "
            "This may indicate a legitimate update or an "
            "unauthorized modification."
        )
        recommended_action = (
            "Verify whether the change was authorized and compare "
            "the file with a trusted version."
        )

    else:
        explanation = (
            "No specific explanation rule exists for this finding."
        )
        recommended_action = (
            "Review the original finding and supporting evidence "
            "before deciding what action to take."
        )

    return {
        "event_type": event_type or "unknown",
        "severity": severity,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "is_ai_generated": False,
    }
