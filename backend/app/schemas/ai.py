from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class KnowledgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    slug: str
    title: str
    category: str
    content: str


class KnowledgeHit(BaseModel):
    id: int
    slug: str
    title: str
    category: str
    relevance_score: float
    snippet: str


class SeedResult(BaseModel):
    inserted: int
    updated: int
    total: int


class InvestigationReport(BaseModel):
    incident_id: int
    mode: Literal["llm", "fallback"]
    generated_by: str  # model name when mode == "llm", otherwise "template (no LLM used)"
    fallback_reason: str | None
    generated_at: datetime
    search_query: str
    retrieved_documents: list[KnowledgeHit]
    report_markdown: str
    approval_notice: str
