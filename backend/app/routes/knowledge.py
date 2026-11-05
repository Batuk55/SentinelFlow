from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.ai import KnowledgeHit, KnowledgeOut, SeedResult
from app.services import knowledge_service

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


@router.get("", response_model=list[KnowledgeOut])
def list_knowledge(db: Session = Depends(get_db)):
    return knowledge_service.list_documents(db)


@router.get("/search", response_model=list[KnowledgeHit])
def search_knowledge(q: str = Query(min_length=2, max_length=200), limit: int = Query(5, ge=1, le=20),
                     db: Session = Depends(get_db)):
    """Full-text search over the knowledge base (the same retrieval the RAG pipeline uses)."""
    _query, hits = knowledge_service.search(db, [q], limit=limit)
    return [{k: v for k, v in h.items() if k != "content"} for h in hits]


@router.post("/seed", response_model=SeedResult)
def seed_knowledge(db: Session = Depends(get_db)):
    """Insert or update the bundled security playbooks. Safe to call repeatedly."""
    return knowledge_service.seed_knowledge(db)
