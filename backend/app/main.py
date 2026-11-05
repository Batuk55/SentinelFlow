import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings
from app.database import SessionLocal, engine, init_db
from app.routes import ai, dashboard, events, incidents, knowledge
from app.services.knowledge_service import seed_knowledge

logger = logging.getLogger("sentinelflow")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    try:  # idempotent: make sure the security playbooks exist
        with SessionLocal() as db:
            seed_knowledge(db)
    except SQLAlchemyError as exc:
        logger.error("Knowledge seed failed: %s", type(exc).__name__)
    yield


app = FastAPI(
    title="SentinelFlow API",
    description="Network threat detection and AI-powered incident management (educational MVP).",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)

app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)
app.include_router(knowledge.router)
app.include_router(ai.router)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(_request: Request, exc: SQLAlchemyError):
    logger.error("Database error: %s", type(exc).__name__)  # do not log statements or parameters
    return JSONResponse(status_code=503, content={"detail": "Database error. Please try again."})


@app.get("/api/health", tags=["system"])
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok", "database": "connected"}
