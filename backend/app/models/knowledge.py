from datetime import datetime

from sqlalchemy import Computed, DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base

# Same expression as database/init.sql. Title weighs most, then category, then body.
_SEARCH_VECTOR_SQL = (
    "setweight(to_tsvector('english', coalesce(title, '')), 'A') || "
    "setweight(to_tsvector('english', coalesce(category, '')), 'B') || "
    "setweight(to_tsvector('english', coalesce(content, '')), 'C')"
)


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (Index("ix_knowledge_search", "search_vector", postgresql_using="gin"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    search_vector = mapped_column(TSVECTOR, Computed(_SEARCH_VECTOR_SQL, persisted=True))
