"""Per-recipient ML-KEM key envelopes for broadcast-encrypted documents."""

from alembic import op
import sqlalchemy as sa

revision = "8b3f6c9e2a14"
down_revision = "5d2e8a1c4f07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "document_recipients",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("document_id", sa.String(length=64), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("kem_ciphertext", sa.Text(), nullable=False),
        sa.Column("wrapped_key", sa.Text(), nullable=False),
        sa.Column("wrap_nonce", sa.String(length=32), nullable=False),
        sa.Column("kdf_info", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("document_id", "recipient_id", name="uq_document_recipient"),
    )
    op.create_index("ix_document_recipients_document_id", "document_recipients", ["document_id"])
    op.create_index("ix_document_recipients_recipient_id", "document_recipients", ["recipient_id"])


def downgrade() -> None:
    op.drop_table("document_recipients")
