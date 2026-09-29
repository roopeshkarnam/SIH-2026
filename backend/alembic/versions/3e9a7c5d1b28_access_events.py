"""Access events: decrypted / previewed / downloaded, per decryption session."""

from alembic import op
import sqlalchemy as sa

revision = "3e9a7c5d1b28"
down_revision = "8b3f6c9e2a14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("session_id", sa.String(length=64), sa.ForeignKey("decryption_sessions.id"), nullable=False),
        sa.Column("document_id", sa.String(length=64), sa.ForeignKey("documents.id"), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("event", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_access_events_session_id", "access_events", ["session_id"])
    op.create_index("ix_access_events_document_id", "access_events", ["document_id"])
    op.create_index("ix_access_events_recipient_id", "access_events", ["recipient_id"])


def downgrade() -> None:
    op.drop_table("access_events")
