
"""Generate offline, evidence-based threat investigation context.

This module interprets existing IP classifications and security events.
It does not independently detect attacks or declare IP addresses malicious.
"""


def analyze_ip_context(ip_intelligence: dict | None) -> dict:
    """Interpret an IP classification without treating it as proof of a threat."""

    if ip_intelligence is None:
        return {
            "classification": "unavailable",
            "context": "No IP intelligence is available for this event.",
            "investigation_required": False,
        }

    if not isinstance(ip_intelligence, dict):
        raise TypeError("ip_intelligence must be a dictionary or None.")

    if not ip_intelligence.get("valid", False):
        return {
            "classification": "invalid",
            "context": "The supplied IP address could not be validated.",
            "investigation_required": True,
        }

    classification = ip_intelligence.get(
        "classification", "unknown"
    )

    contexts = {
        "public": (
            "The address is classified as public. "
            "Public classification does not indicate malicious activity."
        ),
        "private": (
            "The address belongs to a private network range. "
            "Private addresses can still be involved in suspicious activity."
        ),
        "loopback": (
            "The address refers to the local loopback interface. "
            "Review the event's origin and logging context."
        ),
        "link_local": (
            "The address belongs to a link-local range. "
            "Review the local network context."
        ),
        "documentation": (
            "The address belongs to a documentation range and is commonly "
            "used in examples and testing. It should not be treated as "
            "evidence of a real external source."
        ),
        "reserved": (
            "The address belongs to a reserved range. "
            "Review the source data and network context."
        ),
        "unspecified": (
            "The address is an unspecified address rather than a normal "
            "host address. Review how it appeared in the event."
        ),
        "multicast": (
            "The address belongs to a multicast range. "
            "Review the event type and network context."
        ),
        "special": (
            "The address belongs to a special-purpose category. "
            "Additional network context is needed for interpretation."
        ),
    }

    context = contexts.get(
        classification,
        "The IP classification is not recognized. Review the source data.",
    )

    return {
        "classification": classification,
        "context": context,
        "investigation_required": classification in {
            "reserved",
            "unspecified",
            "multicast",
            "special",
            "unknown",
        },
    }


def analyze_event_context(event: dict) -> dict:
    """Interpret a security event using its event type and IP context."""

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary.")

    event_type = event.get("event_type", "unknown")

    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string.")

    ip_context = analyze_ip_context(
        event.get("ip_intelligence")
    )

    if event_type == "failed_login":
        explanation = (
            "A failed login attempt was recorded. A single failed attempt "
            "does not establish malicious activity."
        )
        recommendation = (
            "Review the authentication event and check for repeated "
            "attempts or related successful logins."
        )

    elif event_type == "successful_login":
        explanation = (
            "A successful login was recorded. A successful login alone "
            "does not indicate unauthorized access."
        )
        recommendation = (
            "Verify whether the login was expected and authorized."
        )

    elif event_type == "warning":
        explanation = (
            "A warning event was recorded. Its significance depends "
            "on the event details and surrounding activity."
        )
        recommendation = (
            "Review the warning message and related events."
        )

    elif event_type in {"error", "critical"}:
        explanation = (
            f"A {event_type} event was recorded. Further investigation "
            "is needed to determine its operational or security impact."
        )
        recommendation = (
            "Review the original event, its timestamp, and related "
            "system activity."
        )

    else:
        explanation = (
            "The event type has no specific threat-context rule."
        )
        recommendation = (
            "Review the original event and supporting evidence."
        )

    return {
        "event_type": event_type,
        "explanation": explanation,
        "recommended_action": recommendation,
        "ip_context": ip_context,
        "is_ai_generated": False,
    }


def generate_threat_context(
    events: list,
    findings: list | None = None,
) -> dict:
    """Generate structured investigation context from events and findings."""

    if not isinstance(events, list):
        raise TypeError("events must be a list.")

    if findings is not None and not isinstance(findings, list):
        raise TypeError("findings must be a list or None.")

    event_contexts = [
        analyze_event_context(event)
        for event in events
    ]

    finding_contexts = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            raise TypeError("Each finding must be a dictionary.")

        event_type = finding.get("event_type", "unknown")
        severity = finding.get("severity", "unknown")

        if not isinstance(event_type, str):
            raise ValueError("Finding event_type must be a string.")

        if not isinstance(severity, str):
            raise ValueError("Finding severity must be a string.")

        if event_type == "repeated_failed_login":
            explanation = (
                "Repeated failed login attempts were detected for the "
                "same source. This may indicate brute-force activity, "
                "but does not confirm an attack or account compromise."
            )
            recommendation = (
                "Review the authentication timeline and check whether "
                "any successful login followed the failed attempts."
            )
        else:
            explanation = (
                "This finding requires review of its supporting evidence."
            )
            recommendation = (
                "Verify the finding using the original logs and "
                "related system information."
            )

        finding_contexts.append({
            "event_type": event_type,
            "severity": severity,
            "explanation": explanation,
            "recommended_action": recommendation,
            "is_ai_generated": False,
        })

    return {
        "analysis_type": "offline_threat_context",
        "event_count": len(events),
        "finding_count": len(finding_contexts),
        "event_contexts": event_contexts,
        "finding_contexts": finding_contexts,
        "assessment_note": (
            "This report provides rule-based investigation context. "
            "It does not independently confirm malicious activity "
            "or account compromise."
        ),
        "is_ai_generated": False,
    }
