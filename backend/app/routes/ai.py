from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.ai import InvestigationReport
from app.services import incident_service, rag_service

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.post("/investigate/{incident_id}", response_model=InvestigationReport)
def investigate_incident(incident_id: int, db: Session = Depends(get_db)):
    """Run the RAG pipeline for an incident. Falls back to a clearly labelled template report if no
    LLM is configured or the LLM call fails."""
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return rag_service.investigate(db, incident)
