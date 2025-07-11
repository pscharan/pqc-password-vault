-- Initialize PostgreSQL database for PQC-ZTA Password Vault
-- This script runs automatically when the PostgreSQL container starts

-- Create database if not exists (already created by environment variables)
-- CREATE DATABASE password_vault;

-- Connect to the password_vault database
\c password_vault;

-- Create necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create a dedicated schema for audit functions
CREATE SCHEMA IF NOT EXISTS audit;

-- Create custom types for risk levels
CREATE TYPE risk_level_enum AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE access_decision_enum AS ENUM ('allow', 'deny', 'step_up', 'monitor');
CREATE TYPE authenticator_type_enum AS ENUM ('platform', 'cross-platform');

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create function for secure random ID generation
CREATE OR REPLACE FUNCTION generate_secure_id(length INTEGER DEFAULT 32)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(gen_random_bytes(length), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Create audit logging function
CREATE OR REPLACE FUNCTION audit.log_table_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_entries (
            audit_id, action, user_id, context_data, timestamp
        ) VALUES (
            generate_secure_id(),
            TG_OP || ' on ' || TG_TABLE_NAME,
            COALESCE(NEW.user_id, 'system'),
            jsonb_build_object(
                'table', TG_TABLE_NAME,
                'operation', TG_OP,
                'new_data', row_to_json(NEW)
            ),
            CURRENT_TIMESTAMP
        );
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_entries (
            audit_id, action, user_id, context_data, timestamp
        ) VALUES (
            generate_secure_id(),
            TG_OP || ' on ' || TG_TABLE_NAME,
            COALESCE(NEW.user_id, OLD.user_id, 'system'),
            jsonb_build_object(
                'table', TG_TABLE_NAME,
                'operation', TG_OP,
                'old_data', row_to_json(OLD),
                'new_data', row_to_json(NEW)
            ),
            CURRENT_TIMESTAMP
        );
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_entries (
            audit_id, action, user_id, context_data, timestamp
        ) VALUES (
            generate_secure_id(),
            TG_OP || ' on ' || TG_TABLE_NAME,
            COALESCE(OLD.user_id, 'system'),
            jsonb_build_object(
                'table', TG_TABLE_NAME,
                'operation', TG_OP,
                'old_data', row_to_json(OLD)
            ),
            CURRENT_TIMESTAMP
        );
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Grant necessary permissions to vault_user
GRANT ALL PRIVILEGES ON DATABASE password_vault TO vault_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO vault_user;
GRANT ALL PRIVILEGES ON SCHEMA audit TO vault_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO vault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO vault_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO vault_user;
GRANT ALL ON ALL TABLES IN SCHEMA audit TO vault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA audit TO vault_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA audit TO vault_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vault_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vault_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO vault_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON TABLES TO vault_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON SEQUENCES TO vault_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON FUNCTIONS TO vault_user;

-- Create indexes for performance
-- Note: Actual table creation will be handled by Alembic migrations

-- Performance tuning settings for development
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;

-- Security settings
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = 'on';
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';

-- Reload configuration
SELECT pg_reload_conf();

-- Create a view for monitoring database health
CREATE OR REPLACE VIEW db_health AS
SELECT 
    'PostgreSQL' as service,
    version() as version,
    pg_database_size('password_vault') as database_size,
    pg_size_pretty(pg_database_size('password_vault')) as database_size_pretty,
    (SELECT count(*) FROM pg_stat_activity WHERE datname = 'password_vault') as active_connections,
    current_timestamp as last_check;

-- Create a view for security monitoring
CREATE OR REPLACE VIEW security_overview AS
SELECT 
    'Database Security' as category,
    'Extensions Loaded' as check_name,
    array_to_string(array_agg(extname), ', ') as status
FROM pg_extension
WHERE extname IN ('uuid-ossp', 'pgcrypto')
UNION ALL
SELECT 
    'Database Security' as category,
    'SSL Status' as check_name,
    CASE WHEN ssl THEN 'Enabled' ELSE 'Disabled' END as status
FROM pg_stat_ssl
LIMIT 1;

-- Grant permissions on views
GRANT SELECT ON db_health TO vault_user;
GRANT SELECT ON security_overview TO vault_user;

COMMIT; 