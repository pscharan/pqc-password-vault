"""Initial PQC ZTA schema

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create vault_master table
    op.create_table('vault_master',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('master_password_hash', sa.String(length=255), nullable=True),
        sa.Column('salt', sa.String(length=255), nullable=True),
        sa.Column('encrypted_key', sa.Text(), nullable=True),
        
        # PQC Keys
        sa.Column('kyber_public_key', sa.Text(), nullable=True),
        sa.Column('kyber_private_key', sa.Text(), nullable=True),
        sa.Column('dilithium_public_key', sa.Text(), nullable=True),
        sa.Column('dilithium_private_key', sa.Text(), nullable=True),
        sa.Column('sphincs_public_key', sa.Text(), nullable=True),
        sa.Column('sphincs_private_key', sa.Text(), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vault_master_id'), 'vault_master', ['id'], unique=False)
    op.create_index(op.f('ix_vault_master_name'), 'vault_master', ['name'], unique=True)

    # Create password_entries table
    op.create_table('password_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vault_id', sa.Integer(), nullable=True),
        sa.Column('service_name', sa.String(length=255), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        
        # Classical encryption
        sa.Column('encrypted_password', sa.Text(), nullable=True),
        sa.Column('encrypted_notes', sa.Text(), nullable=True),
        
        # PQC encryption
        sa.Column('pqc_encrypted_password', sa.Text(), nullable=True),
        sa.Column('pqc_encrypted_notes', sa.Text(), nullable=True),
        
        # Additional fields
        sa.Column('website_url', sa.String(length=500), nullable=True),
        sa.Column('tags', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=True),
        
        sa.ForeignKeyConstraint(['vault_id'], ['vault_master.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_password_entries_id'), 'password_entries', ['id'], unique=False)
    op.create_index(op.f('ix_password_entries_vault_id'), 'password_entries', ['vault_id'], unique=False)
    op.create_index(op.f('ix_password_entries_service_name'), 'password_entries', ['service_name'], unique=False)
    op.create_index(op.f('ix_password_entries_username'), 'password_entries', ['username'], unique=False)

    # Create webauthn_credentials table
    op.create_table('webauthn_credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('credential_id', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('public_key', sa.Text(), nullable=True),
        sa.Column('counter', sa.Integer(), nullable=True),
        sa.Column('authenticator_type', sa.String(length=50), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_used', sa.DateTime(), nullable=True),
        sa.Column('usage_count', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        
        # Device information
        sa.Column('device_name', sa.String(length=255), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webauthn_credentials_credential_id'), 'webauthn_credentials', ['credential_id'], unique=True)
    op.create_index(op.f('ix_webauthn_credentials_user_id'), 'webauthn_credentials', ['user_id'], unique=False)

    # Create user_sessions table
    op.create_table('user_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('vault_id', sa.Integer(), nullable=True),
        
        # Session data
        sa.Column('encrypted_vault_key', sa.Text(), nullable=True),
        
        # ZTA context
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('geolocation', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('anomaly_score', sa.Float(), nullable=True),
        
        # Session metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_activity', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        
        sa.ForeignKeyConstraint(['vault_id'], ['vault_master.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_session_id'), 'user_sessions', ['session_id'], unique=True)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_sessions_vault_id'), 'user_sessions', ['vault_id'], unique=False)

    # Create device_contexts table
    op.create_table('device_contexts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        
        # Device information
        sa.Column('device_fingerprint', sa.String(length=255), nullable=True),
        sa.Column('device_name', sa.String(length=255), nullable=True),
        sa.Column('device_type', sa.String(length=50), nullable=True),
        
        # Trust information
        sa.Column('is_trusted', sa.Boolean(), nullable=True),
        sa.Column('trust_score', sa.Float(), nullable=True),
        
        # Location tracking
        sa.Column('last_known_location', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('location_history', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_contexts_device_id'), 'device_contexts', ['device_id'], unique=True)
    op.create_index(op.f('ix_device_contexts_user_id'), 'device_contexts', ['user_id'], unique=False)

    # Create audit_entries table
    op.create_table('audit_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('audit_id', sa.String(length=255), nullable=True),
        
        # Audit information
        sa.Column('action', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('vault_id', sa.Integer(), nullable=True),
        sa.Column('password_entry_id', sa.Integer(), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        
        # Context information
        sa.Column('context_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('device_id', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        
        # PQC signature for integrity
        sa.Column('audit_signature', sa.Text(), nullable=True),
        sa.Column('signature_algorithm', sa.String(length=50), nullable=True),
        
        # Metadata
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        
        sa.ForeignKeyConstraint(['password_entry_id'], ['password_entries.id'], ),
        sa.ForeignKeyConstraint(['session_id'], ['user_sessions.session_id'], ),
        sa.ForeignKeyConstraint(['vault_id'], ['vault_master.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_entries_audit_id'), 'audit_entries', ['audit_id'], unique=True)
    op.create_index(op.f('ix_audit_entries_action'), 'audit_entries', ['action'], unique=False)
    op.create_index(op.f('ix_audit_entries_user_id'), 'audit_entries', ['user_id'], unique=False)

    # Create policy_decisions table
    op.create_table('policy_decisions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('decision_id', sa.String(length=255), nullable=True),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=255), nullable=True),
        sa.Column('resource', sa.String(length=255), nullable=True),
        
        # Decision result
        sa.Column('decision', sa.String(length=50), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(length=50), nullable=True),
        
        # Policy information
        sa.Column('policy_name', sa.String(length=255), nullable=True),
        sa.Column('policy_result', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        
        # Metadata
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_policy_decisions_decision_id'), 'policy_decisions', ['decision_id'], unique=True)
    op.create_index(op.f('ix_policy_decisions_user_id'), 'policy_decisions', ['user_id'], unique=False)
    op.create_index(op.f('ix_policy_decisions_action'), 'policy_decisions', ['action'], unique=False)
    op.create_index(op.f('ix_policy_decisions_resource'), 'policy_decisions', ['resource'], unique=False)

    # Create PostgreSQL extensions (if needed)
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('policy_decisions')
    op.drop_table('audit_entries')
    op.drop_table('device_contexts')
    op.drop_table('user_sessions')
    op.drop_table('webauthn_credentials')
    op.drop_table('password_entries')
    op.drop_table('vault_master')
    
    # Drop extensions
    op.execute('DROP EXTENSION IF EXISTS "uuid-ossp"') 