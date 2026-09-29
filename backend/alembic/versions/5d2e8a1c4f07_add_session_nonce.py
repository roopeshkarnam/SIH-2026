"""Add decryption_sessions.session_nonce (fixes drift between model and initial migration).

Idempotent: the shared database already has this column (it was created
outside Alembic), so the column is only added when it is missing.
"""

from alembic import op
import sqlalchemy as sa

revision = "5d2e8a1c4f07"
down_revision = "bc7be07d1985"
branch_labels = None
depends_on = None


def _has_session_nonce() -> bool:
    columns = sa.inspect(op.get_bind()).get_columns("decryption_sessions")
    return any(c["name"] == "session_nonce" for c in columns)


def upgrade() -> None:
    if _has_session_nonce():
        return
    # Batch mode: SQLite cannot ADD COLUMN ... NOT NULL without a default.
    with op.batch_alter_table("decryption_sessions") as batch:
        batch.add_column(sa.Column("session_nonce", sa.String(), nullable=False))


def downgrade() -> None:
    if not _has_session_nonce():
        return
    with op.batch_alter_table("decryption_sessions") as batch:
        batch.drop_column("session_nonce")
