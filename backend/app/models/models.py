from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    role: Mapped[str] = mapped_column(
        String(50),
        default="recipient",
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    documents = relationship(
        "Document",
        back_populates="owner",
    )


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    mime_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    storage_path: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )

    encrypted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    owner = relationship(
        "User",
        back_populates="documents",
    )

    sessions = relationship(
        "DecryptionSession",
        back_populates="document",
    )


class DecryptionSession(Base):
    __tablename__ = "decryption_sessions"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    document_id: Mapped[str] = mapped_column(
        ForeignKey("documents.id"),
        nullable=False,
    )

    recipient_id: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="started",
        nullable=False,
    )

    session_nonce: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    document = relationship(
        "Document",
        back_populates="sessions",
    )

    watermark = relationship(
        "Watermark",
        back_populates="session",
        uselist=False,
    )

    provenance = relationship(
        "ProvenanceRecord",
        back_populates="session",
        uselist=False,
    )


class Watermark(Base):
    __tablename__ = "watermarks"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    session_id: Mapped[str] = mapped_column(
        ForeignKey("decryption_sessions.id"),
        unique=True,
        nullable=False,
    )

    watermark_token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )

    algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    session = relationship(
        "DecryptionSession",
        back_populates="watermark",
    )


class ProvenanceRecord(Base):
    __tablename__ = "provenance_records"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    session_id: Mapped[str] = mapped_column(
        ForeignKey("decryption_sessions.id"),
        unique=True,
        nullable=False,
    )

    document_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    recipient_id: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )

    watermark_id: Mapped[str] = mapped_column(
        ForeignKey("watermarks.id"),
        nullable=False,
    )

    signature_algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    record_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    ledger_transaction_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    session = relationship(
        "DecryptionSession",
        back_populates="provenance",
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    actor_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )