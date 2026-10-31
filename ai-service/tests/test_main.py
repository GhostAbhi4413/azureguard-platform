from fastapi.testclient import TestClient

from app.main import Finding, Remediation, create_app, sanitize_finding


class MockAI:
    async def explain(self, finding: Finding) -> Remediation:
        return Remediation(
            explanation=f"{finding.finding_id} indicates a possible weakness.",
            potential_impact="An attacker may gain unauthorized access.",
            suggested_remediation="Apply the vendor fix and rotate exposed credentials.",
            prevention_measures=["Add a regression security test."],
        )


def test_remediation_contract_accepts_csharp_camel_case_and_returns_structured_guidance():
    response = TestClient(create_app(MockAI())).post(
        "/api/remediation",
        json={
            "scanner": "GITLEAKS", "findingId": "rule-1", "severity": "CRITICAL",
            "fileLocation": "config/app.json", "description": "Potential token exposure",
            "commitReference": "abc123",
        },
    )
    assert response.status_code == 200
    assert response.json()["suggestedRemediation"].startswith("Apply")
    assert response.json()["preventionMeasures"] == ["Add a regression security test."]


def test_invalid_severity_is_rejected():
    response = TestClient(create_app(MockAI())).post(
        "/api/remediation",
        json={"scanner": "demo", "findingId": "1", "severity": "UNKNOWN", "description": "bad"},
    )
    assert response.status_code == 422


def test_sanitizer_redacts_credentials_and_omits_source_like_descriptions():
    credential = Finding(scanner="GITLEAKS", findingId="rule-1", severity="CRITICAL", description="token=do-not-send")
    assert "do-not-send" not in sanitize_finding(credential).description
    source = Finding(scanner="SAST", findingId="rule-2", severity="HIGH", description="private source\nclass SecretCode {}")
    assert "private source" not in sanitize_finding(source).description
