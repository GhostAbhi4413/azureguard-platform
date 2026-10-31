from fastapi.testclient import TestClient

from app.main import Remediation, create_app


class MockAI:
    async def explain(self, finding):
        return Remediation(
            explanation=f"{finding.finding_id} indicates a possible weakness.",
            potential_impact="An attacker may gain unauthorized access.",
            suggested_remediation="Apply the vendor fix and rotate exposed credentials.",
            prevention_measures=["Add a regression security test."],
        )


def test_remediation_uses_mocked_client():
    response = TestClient(create_app(MockAI())).post(
        "/api/remediation",
        json={"scanner": "GITLEAKS", "finding_id": "rule-1", "severity": "CRITICAL",
              "file_location": "config/app.json", "description": "Potential token exposure"},
    )
    assert response.status_code == 200
    assert response.json()["suggested_remediation"].startswith("Apply")


def test_invalid_severity_is_rejected():
    response = TestClient(create_app(MockAI())).post(
        "/api/remediation",
        json={"scanner": "demo", "finding_id": "1", "severity": "UNKNOWN", "description": "bad"},
    )
    assert response.status_code == 422
