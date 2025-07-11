#!/bin/bash

# PQC-ZTA Password Vault Setup Script
# This script sets up the complete development environment

set -e # Exit on any error

echo "🔐 Setting up PQC-ZTA Password Vault System..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker and Docker Compose are installed
check_dependencies() {
    print_status "Checking dependencies..."

    if ! command -v docker &>/dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &>/dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    print_success "Dependencies check passed"
}

# Generate environment variables
generate_env() {
    print_status "Generating environment variables..."

    if [ ! -f .env ]; then
        cat >.env <<EOF
# PQC-ZTA Password Vault Environment Variables

# JWT Configuration
JWT_SECRET_KEY=$(openssl rand -hex 32)
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Database Configuration
DATABASE_URL=postgresql://vault_user:vault_password@localhost:5432/password_vault
POSTGRES_DB=password_vault
POSTGRES_USER=vault_user
POSTGRES_PASSWORD=vault_password

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# OPA Configuration
OPA_URL=http://localhost:8181

# WebAuthn Configuration
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=PQC Password Vault
WEBAUTHN_ORIGIN=http://localhost:3000

# API Configuration
API_BASE_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WEBAUTHN_ORIGIN=http://localhost:3000
NEXT_PUBLIC_WEBAUTHN_RP_ID=localhost

# Monitoring Configuration
PROMETHEUS_URL=http://localhost:9090
GRAFANA_URL=http://localhost:3001

# Development Settings
DEBUG=true
LOG_LEVEL=INFO
ENVIRONMENT=development
EOF
        print_success "Environment file created"
    else
        print_warning "Environment file already exists, skipping..."
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."

    mkdir -p monitoring/grafana/provisioning/dashboards
    mkdir -p monitoring/grafana/provisioning/datasources
    mkdir -p opa-policies
    mkdir -p ssl
    mkdir -p logs

    print_success "Directories created"
}

# Create monitoring configuration
create_monitoring_config() {
    print_status "Creating monitoring configuration..."

    # Prometheus configuration
    cat >monitoring/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'dashboard'
    static_configs:
      - targets: ['dashboard:8501']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    scrape_interval: 10s

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    scrape_interval: 10s

  - job_name: 'opa'
    static_configs:
      - targets: ['opa:8181']
    metrics_path: '/metrics'
    scrape_interval: 10s
EOF

    # Grafana datasource configuration
    cat >monitoring/grafana/provisioning/datasources/prometheus.yml <<EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    # Grafana dashboard configuration
    cat >monitoring/grafana/provisioning/dashboards/dashboard.yml <<EOF
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

    print_success "Monitoring configuration created"
}

# Create Celery configuration
create_celery_config() {
    print_status "Creating Celery configuration..."

    cat >pass_vault/celery_app.py <<EOF
# Celery configuration for background tasks

from celery import Celery
import os

# Redis URL from environment
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Create Celery app
app = Celery('password_vault')

# Configure Celery
app.conf.update(
    broker_url=redis_url,
    result_backend=redis_url,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_routes={
        'session_cleanup': {'queue': 'cleanup'},
        'audit_log_processing': {'queue': 'audit'},
        'risk_score_calculation': {'queue': 'analysis'},
    },
    beat_schedule={
        'cleanup-expired-sessions': {
            'task': 'session_cleanup',
            'schedule': 300.0,  # Every 5 minutes
        },
        'process-audit-logs': {
            'task': 'audit_log_processing',
            'schedule': 60.0,   # Every minute
        },
        'calculate-risk-scores': {
            'task': 'risk_score_calculation',
            'schedule': 900.0,  # Every 15 minutes
        },
    },
)

# Import tasks
from tasks import *

if __name__ == '__main__':
    app.start()
EOF

    cat >pass_vault/tasks.py <<EOF
# Background tasks for the password vault

from celery_app import app
from api.auth import cleanup_expired_sessions, get_session_stats
import logging

logger = logging.getLogger(__name__)

@app.task(name='session_cleanup')
def cleanup_sessions_task():
    """Clean up expired sessions."""
    try:
        cleaned = cleanup_expired_sessions()
        logger.info(f"Cleaned up {cleaned} expired sessions")
        return f"Cleaned up {cleaned} sessions"
    except Exception as e:
        logger.error(f"Session cleanup failed: {e}")
        return f"Error: {str(e)}"

@app.task(name='audit_log_processing')
def process_audit_logs():
    """Process and analyze audit logs."""
    try:
        # This would implement audit log processing
        logger.info("Processing audit logs")
        return "Audit logs processed"
    except Exception as e:
        logger.error(f"Audit log processing failed: {e}")
        return f"Error: {str(e)}"

@app.task(name='risk_score_calculation')
def calculate_risk_scores():
    """Calculate and update risk scores."""
    try:
        stats = get_session_stats()
        logger.info(f"Risk analysis completed: {stats}")
        return f"Risk scores calculated: {stats}"
    except Exception as e:
        logger.error(f"Risk score calculation failed: {e}")
        return f"Error: {str(e)}"
EOF

    print_success "Celery configuration created"
}

# Run database migrations
run_migrations() {
    print_status "Preparing database migrations..."

    # Wait for PostgreSQL to be ready
    print_status "Waiting for PostgreSQL to be ready..."
    until docker-compose exec -T postgres pg_isready -U vault_user -d password_vault; do
        print_status "PostgreSQL is unavailable - sleeping"
        sleep 2
    done

    print_success "PostgreSQL is ready"

    # Run Alembic migrations
    print_status "Running database migrations..."
    cd pass_vault
    docker-compose exec -T backend alembic upgrade head
    cd ..

    print_success "Database migrations completed"
}

# Start services
start_services() {
    print_status "Starting core services..."

    # Start infrastructure services first
    docker-compose up -d postgres redis opa

    print_status "Waiting for infrastructure services to be ready..."
    sleep 10

    # Start application services
    docker-compose up -d backend dashboard celery-worker celery-beat

    print_status "Starting frontend..."
    docker-compose up -d frontend

    print_success "All services started"
}

# Display service status
show_status() {
    print_status "Checking service status..."
    docker-compose ps

    echo ""
    print_success "🚀 PQC-ZTA Password Vault is ready!"
    echo ""
    echo "📱 Services:"
    echo "  • Frontend:     http://localhost:3000"
    echo "  • Backend API:  http://localhost:8000"
    echo "  • Dashboard:    http://localhost:8501"
    echo "  • OPA:          http://localhost:8181"
    echo "  • PostgreSQL:   localhost:5432"
    echo "  • Redis:        localhost:6379"
    echo ""
    echo "📊 Monitoring (optional):"
    echo "  • Prometheus:   http://localhost:9090"
    echo "  • Grafana:      http://localhost:3001 (admin/admin)"
    echo ""
    echo "🔧 Management:"
    echo "  • View logs:    docker-compose logs -f [service]"
    echo "  • Stop all:     docker-compose down"
    echo "  • Restart:      docker-compose restart [service]"
    echo ""
    print_warning "Default credentials are for development only!"
    echo ""
}

# Start monitoring (optional)
start_monitoring() {
    read -p "Do you want to start monitoring services (Prometheus/Grafana)? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Starting monitoring services..."
        docker-compose --profile monitoring up -d
        print_success "Monitoring services started"
    fi
}

# Main execution
main() {
    echo "🔐 PQC-ZTA Password Vault Setup"
    echo "================================"
    echo ""

    check_dependencies
    generate_env
    create_directories
    create_monitoring_config
    create_celery_config

    # Build and start services
    print_status "Building Docker images..."
    docker-compose build

    start_services

    # Run migrations after services are up
    run_migrations

    show_status
    start_monitoring

    print_success "Setup completed successfully! 🎉"
}

# Handle script arguments
case "${1:-}" in
"start")
    start_services
    show_status
    ;;
"stop")
    print_status "Stopping all services..."
    docker-compose down
    print_success "All services stopped"
    ;;
"restart")
    print_status "Restarting services..."
    docker-compose restart
    show_status
    ;;
"logs")
    docker-compose logs -f "${2:-}"
    ;;
"status")
    show_status
    ;;
"clean")
    print_warning "This will remove all containers, volumes, and data!"
    read -p "Are you sure? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v --remove-orphans
        docker system prune -f
        print_success "Cleanup completed"
    fi
    ;;
*)
    main
    ;;
esac
