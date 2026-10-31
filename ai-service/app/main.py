import os
import re
from typing import Protocol

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field


def camel_case(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.title() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=camel_case, populate_by_name=True)


class Finding(ApiModel):
    scanner: str = Field(min_length=1, max_length=80)
    finding_id: str = Field(min_length=1, max_length=160)
    severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    file_location: str | None = Field(default=None, max_length=240)
    description: str = Field(min_length=1, max_length=1200)
    commit_reference: str | None = Field(default=None, max_length=80)


class Remediation(ApiModel):
    explanation: str
    potential_impact: str
    suggested_remediation: str
    prevention_measures: list[str]


class AIClient(Protocol):
    async def explain(self, finding: Finding) -> Remediation: ...


class AzureOpenAIClient:
    def __init__(self) -> None:
        from openai import AsyncAzureOpenAI

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_API_KEY")
        if not endpoint or not key:
            raise RuntimeError("Azure OpenAI is not configured")
        self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        if not self.deployment:
            raise RuntimeError("AZURE_OPENAI_DEPLOYMENT is not configured")
        self.client = AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
            timeout=20.0,
            max_retries=2,
        )

    async def explain(self, finding: Finding) -> Remediation:
        import json

        safe_finding = finding.model_copy(update={
            "description": re.sub(
                r"(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*[^\s,;]+|Bearer\s+[A-Za-z0-9._~+/-]+=*",
                "[REDACTED]",
                finding.description,
            )
        })
        prompt = (
            "Give defensive remediation guidance for this sanitized security finding. "
            "Do not infer or request source code, secrets, or credentials. Return JSON fields "
            "explanation, potential_impact, suggested_remediation, prevention_measures. Finding: "
            + safe_finding.model_dump_json()
        )
        result = await self.client.chat.completions.create(
            model=self.deployment,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
        )
        content = result.choices[0].message.content or "{}"
        return Remediation.model_validate(json.loads(content))


def create_app(client: AIClient | None = None) -> FastAPI:
    app = FastAPI(title="AzureGuard AI Remediation", version="1.0.0")
    app.state.ai_client = client

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/remediation", response_model=Remediation)
    async def remediation(finding: Finding) -> Remediation:
        ai_client = app.state.ai_client
        if ai_client is None:
            try:
                ai_client = AzureOpenAIClient()
                app.state.ai_client = ai_client
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail="AI remediation is not configured") from exc
        try:
            return await ai_client.explain(finding)
        except Exception as exc:
            # Do not return provider details, prompts, or credentials to callers.
            raise HTTPException(status_code=502, detail="AI remediation provider request failed") from exc

    return app


app = create_app()
