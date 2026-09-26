"""Initial SIH security schema."""

from alembic import op
import sqlalchemy as sa

revision = "bc7be07d1985"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("kem_public_key", sa.Text(), nullable=True),
        sa.Column("sig_public_key", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "documents",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("owner_id", sa.String(length=64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("document_hash", sa.String(length=64), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_documents_owner_id", "documents", ["owner_id"])
    op.create_index("ix_documents_document_hash", "documents", ["document_hash"])

    op.create_table(
        "decryption_sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("document_id", sa.String(length=64), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("watermark_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_decryption_sessions_document_id", "decryption_sessions", ["document_id"])
    op.create_index("ix_decryption_sessions_recipient_id", "decryption_sessions", ["recipient_id"])
    op.create_index("ix_decryption_sessions_watermark_id", "decryption_sessions", ["watermark_id"], unique=True)

    op.create_table(
        "provenance_records",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("document_id", sa.String(length=64), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("session_id", sa.String(length=64), sa.ForeignKey("decryption_sessions.id"), nullable=False),
        sa.Column("watermark_id", sa.String(length=64), nullable=False),
        sa.Column("document_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=50), nullable=False),
        sa.Column("ledger_transaction_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_provenance_records_document_id", "provenance_records", ["document_id"])
    op.create_index("ix_provenance_records_recipient_id", "provenance_records", ["recipient_id"])
    op.create_index("ix_provenance_records_session_id", "provenance_records", ["session_id"])
    op.create_index("ix_provenance_records_watermark_id", "provenance_records", ["watermark_id"], unique=True)


def downgrade() -> None:
    op.drop_table("provenance_records")
    op.drop_table("decryption_sessions")
    op.drop_table("documents")
    op.drop_table("users")
