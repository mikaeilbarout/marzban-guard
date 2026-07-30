"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-30
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

user_status_enum = postgresql.ENUM(
    "active", "suspended", "disabled", "blacklisted", name="user_status"
)


def upgrade() -> None:
    user_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "guard_users",
        sa.Column("username", sa.String(), primary_key=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column(
            "status",
            postgresql.ENUM("active", "suspended", "disabled", "blacklisted", name="user_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
        sa.Column("status_reason", sa.String(), nullable=True),
        sa.Column("status_expires_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_node_id", sa.String(), nullable=True),
        sa.Column("last_abuse_event_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "abuse_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), sa.ForeignKey("guard_users.username"), nullable=False),
        sa.Column("detector", sa.String(), nullable=False),
        sa.Column("score_delta", sa.Float(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_abuse_events_username", "abuse_events", ["username"])
    op.create_index("ix_abuse_events_created_at", "abuse_events", ["created_at"])

    op.create_table(
        "mitigation_actions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), sa.ForeignKey("guard_users.username"), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=False, server_default="system"),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("reverted_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_mitigation_actions_username", "mitigation_actions", ["username"])
    op.create_index("ix_mitigation_actions_created_at", "mitigation_actions", ["created_at"])

    op.create_table(
        "blacklist_entries",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reviewed_by", sa.String(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_blacklist_entries_username", "blacklist_entries", ["username"])

    op.create_table(
        "connection_rollups",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("node_id", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(), nullable=False),
        sa.Column("new_connections_tcp", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_connections_udp", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("distinct_destination_ips", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("distinct_destination_ports", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("top_destination_country", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_connection_rollups_username", "connection_rollups", ["username"])
    op.create_index("ix_connection_rollups_window_start", "connection_rollups", ["window_start"])

    op.create_table(
        "traffic_samples",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("node_id", sa.String(), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("online", sa.Boolean(), nullable=False),
        sa.Column("sampled_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_traffic_samples_username", "traffic_samples", ["username"])
    op.create_index("ix_traffic_samples_sampled_at", "traffic_samples", ["sampled_at"])


def downgrade() -> None:
    op.drop_table("traffic_samples")
    op.drop_table("connection_rollups")
    op.drop_table("blacklist_entries")
    op.drop_table("mitigation_actions")
    op.drop_table("abuse_events")
    op.drop_table("guard_users")
    user_status_enum.drop(op.get_bind(), checkfirst=True)
