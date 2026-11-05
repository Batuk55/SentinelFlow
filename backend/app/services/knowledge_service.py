"""Knowledge base management and PostgreSQL full-text retrieval."""
from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.data.knowledge_base import KNOWLEDGE_DOCUMENTS
from app.models import KnowledgeDocument


def seed_knowledge(db: Session) -> dict:
    """Insert or update the bundled documents (idempotent, keyed by slug)."""
    existing = {d.slug: d for d in db.scalars(select(KnowledgeDocument))}
    inserted = updated = 0
    for doc in KNOWLEDGE_DOCUMENTS:
        row = existing.get(doc["slug"])
        if row is None:
            db.add(KnowledgeDocument(**doc))
            inserted += 1
        elif (row.title, row.category, row.content) != (doc["title"], doc["category"], doc["content"]):
            row.title, row.category, row.content = doc["title"], doc["category"], doc["content"]
            updated += 1
    db.commit()
    total = db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0
    return {"inserted": inserted, "updated": updated, "total": total}


def list_documents(db: Session) -> list[KnowledgeDocument]:
    return list(db.scalars(select(KnowledgeDocument).order_by(KnowledgeDocument.id)))


def build_or_query(terms: list[str]) -> str:
    """Turn free text/terms into a safe OR tsquery string like 'brute | force | login'."""
    words: list[str] = []
    for term in terms:
        for word in re.findall(r"[a-z0-9]+", term.lower()):
            if len(word) > 2 and word not in words:
                words.append(word)
    return " | ".join(words)


def search(db: Session, terms: list[str], limit: int = 4) -> tuple[str, list[dict]]:
    """Ranked full-text search. Returns (tsquery_string, hits).

    Uses to_tsquery with OR semantics (so one missing word does not zero out results), the stored
    weighted tsvector (GIN-indexed) and ts_rank_cd cover-density ranking.
    """
    query_text = build_or_query(terms)
    if not query_text:
        return "", []
    tsquery = func.to_tsquery("english", query_text)
    rank = func.ts_rank_cd(KnowledgeDocument.search_vector, tsquery).label("score")
    snippet = func.ts_headline(
        "english", KnowledgeDocument.content, tsquery, "MaxWords=35, MinWords=15, ShortWord=3"
    ).label("snippet")
    stmt = (
        select(KnowledgeDocument, rank, snippet)
        .where(KnowledgeDocument.search_vector.op("@@")(tsquery))
        .order_by(rank.desc(), KnowledgeDocument.id)
        .limit(limit)
    )
    hits = [
        {
            "id": doc.id, "slug": doc.slug, "title": doc.title, "category": doc.category,
            "relevance_score": round(float(score), 4), "snippet": " ".join(snip.split()),
            "content": doc.content,
        }
        for doc, score, snip in db.execute(stmt)
    ]
    return query_text, hits
