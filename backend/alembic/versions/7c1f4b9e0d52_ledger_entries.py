"""Tamper-evident ledger: hash-chained, ML-DSA-signed entries."""

from alembic import op
import sqlalchemy as sa

revision = "7c1f4b9e0d52"
down_revision = "3e9a7c5d1b28"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ledger_entries",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("signature", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ledger_entries")
