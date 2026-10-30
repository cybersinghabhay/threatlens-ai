from threatlens_ai.finding_explainer import explain_finding

def explain_repeated_failed_login(findings: list) -> list:
    """Generate explanations for repeated failed-login findings."""

    if not isinstance(findings, list):
        raise TypeError("findings must be a list")

    explained_findings = []

    for finding in findings:
        if not isinstance(finding, dict):
            raise TypeError("Each finding must be a dictionary")

        explanation = explain_finding({
            "event_type": "repeated_failed_login",
            "severity": finding.get("severity", "unknown"),
        })

        explained_findings.append({
            **finding,
            **explanation,
        })

    return explained_findings