import json
import logging
import os
import re
from typing import Protocol

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("azureguard.ai")


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


SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|password|token|authorization)\s*[:=]\s*[^\s,;]+|Bearer\s+[A-Za-z0-9._~+/-]+=*"
)
SOURCE_PATTERN = re.compile(
    r"(?im)^\s*(?:using|import|namespace|class|def|function)\s+|\b(?:const|let|var)\s+\w+\s*=|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+"
)


def sanitize_finding(finding: Finding) -> Finding:
    description = SECRET_PATTERN.sub("[REDACTED]", finding.description)
    if "\n" in description or "\r" in description or SOURCE_PATTERN.search(description):
        description = "[scanner description omitted because it contains source-like content]"
    return finding.model_copy(update={"description": description})


class AzureOpenAIClient:
    def __init__(self) -> None:
        from openai import AsyncAzureOpenAI

        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        key = os.getenv("AZURE_OPENAI_API_KEY")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
        if not endpoint or not key or not deployment:
            raise RuntimeError("Azure OpenAI is not configured")
        self.deployment = deployment
        try:
            timeout = float(os.getenv("AZURE_OPENAI_TIMEOUT_SECONDS", "25"))
        except ValueError as exc:
            raise RuntimeError("Azure OpenAI timeout configuration is invalid") from exc
        if not 1 <= timeout <= 120:
            raise RuntimeError("Azure OpenAI timeout must be between 1 and 120 seconds")
        self.client = AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21"),
            timeout=timeout,
            max_retries=2,
        )

    async def explain(self, finding: Finding) -> Remediation:
        safe_finding = sanitize_finding(finding)
        prompt = (
            "Give concise defensive remediation guidance for the sanitized security finding. "
            "Use only finding metadata. Never request or infer source code or secrets. "
            "Return JSON fields explanation, potentialImpact, suggestedRemediation, "
            "and preventionMeasures. Finding: " + safe_finding.model_dump_json(by_alias=True)
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
            except Exception as exc:
                logger.warning("Azure OpenAI configuration failed (%s)", type(exc).__name__)
                raise HTTPException(status_code=503, detail="AI remediation is not configured") from exc
        try:
            return await ai_client.explain(finding)
        except Exception as exc:
            logger.warning("Azure OpenAI remediation request failed (%s)", type(exc).__name__)
            raise HTTPException(status_code=502, detail="AI remediation provider request failed") from exc

    return app


app = create_app()
