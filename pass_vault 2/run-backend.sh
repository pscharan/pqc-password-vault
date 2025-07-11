#!/bin/bash

# PQC-ZTA Password Vault Backend Launcher
set -e # Exit on any error

echo "🚀 Starting PQC-ZTA Password Vault Backend..."
echo "🔒 Post-Quantum Cryptography enabled Zero Trust Architecture"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
if ! command -v python3 &>/dev/null; then
    print_error "Python 3 is required but not installed."
    exit 1
fi

# Check Python version (3.8+)
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_error "Python 3.8+ is required. Current version: $python_version"
    exit 1
fi

print_status "Python $python_version detected ✓"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -eq 0 ]; then
        print_status "Virtual environment created ✓"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
else
    print_status "Virtual environment found ✓"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip >/dev/null 2>&1

# Install dependencies
print_status "Installing/updating dependencies..."
if [ -f "pass_vault/requirements.txt" ]; then
    pip install -r pass_vault/requirements.txt
    if [ $? -eq 0 ]; then
        print_status "Dependencies installed ✓"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
else
    print_error "requirements.txt not found in pass_vault/"
    exit 1
fi

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Check for environment configuration
if [ ! -f "pass_vault/.env" ]; then
    if [ -f "pass_vault/config.template" ]; then
        print_warning "No .env file found. Copying from config.template..."
        cp pass_vault/config.template pass_vault/.env
        print_warning "Please edit pass_vault/.env with your configuration before running the server."
        echo ""
        echo -e "${YELLOW}Required configuration:${NC}"
        echo "  - DATABASE_URL (PostgreSQL connection)"
        echo "  - SECRET_KEY (Flask secret key)"
        echo "  - JWT_SECRET_KEY (JWT signing key)"
        echo "  - REDIS_URL (Redis connection for sessions)"
        echo ""
        echo -e "${BLUE}To continue with default settings, press Enter...${NC}"
        read -p ""
    else
        print_warning "No configuration file found. Using environment defaults."
    fi
fi

# Load environment variables if .env exists
if [ -f "pass_vault/.env" ]; then
    print_status "Loading environment configuration..."
    export $(grep -v '^#' pass_vault/.env | xargs)
fi

# Check for required services
print_status "Checking required services..."

# Check PostgreSQL connection
if command -v pg_isready &>/dev/null; then
    if pg_isready -h "${DB_HOST:-localhost}" -p "${DB_PORT:-5432}" &>/dev/null; then
        print_status "PostgreSQL connection ✓"
    else
        print_warning "PostgreSQL not accessible. Make sure it's running."
        print_warning "You can start it with Docker: docker-compose up -d postgres"
    fi
else
    print_warning "pg_isready not available. Assuming PostgreSQL is running."
fi

# Check Redis connection
if command -v redis-cli &>/dev/null; then
    if redis-cli -h "${REDIS_HOST:-localhost}" -p "${REDIS_PORT:-6379}" ping &>/dev/null; then
        print_status "Redis connection ✓"
    else
        print_warning "Redis not accessible. Make sure it's running."
        print_warning "You can start it with Docker: docker-compose up -d redis"
    fi
else
    print_warning "redis-cli not available. Assuming Redis is running."
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p backups
mkdir -p data

# Run database migrations
print_status "Running database migrations..."
cd pass_vault
if [ -f "alembic.ini" ]; then
    alembic upgrade head
    if [ $? -eq 0 ]; then
        print_status "Database migrations completed ✓"
    else
        print_warning "Database migrations failed. Continuing anyway..."
    fi
else
    print_warning "Alembic configuration not found. Skipping migrations."
fi

# Parse command line arguments
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
CONFIG="${CONFIG:-development}"

while [[ $# -gt 0 ]]; do
    case $1 in
    --host)
        HOST="$2"
        shift 2
        ;;
    --port)
        PORT="$2"
        shift 2
        ;;
    --config)
        CONFIG="$2"
        shift 2
        ;;
    --setup)
        print_status "Running setup mode..."
        python main.py --setup
        exit 0
        ;;
    --dashboard)
        print_status "Starting dashboard mode..."
        python main.py --mode dashboard
        exit 0
        ;;
    -h | --help)
        echo "PQC-ZTA Password Vault Backend Launcher"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --host HOST      Server host (default: 0.0.0.0)"
        echo "  --port PORT      Server port (default: 8000)"
        echo "  --config CONFIG  Configuration mode: development|production (default: development)"
        echo "  --setup          Run initial setup and migrations"
        echo "  --dashboard      Start dashboard mode"
        echo "  -h, --help       Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  DATABASE_URL     PostgreSQL connection string"
        echo "  REDIS_URL        Redis connection string"
        echo "  SECRET_KEY       Flask secret key"
        echo "  JWT_SECRET_KEY   JWT signing key"
        echo ""
        exit 0
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
    esac
done

# Final status check
print_status "Configuration:"
echo "  Host: $HOST"
echo "  Port: $PORT"
echo "  Config: $CONFIG"
echo "  Database: ${DATABASE_URL:-Not configured}"
echo "  Redis: ${REDIS_URL:-Not configured}"
echo ""

# Run the backend server
print_status "Starting PQC-ZTA Password Vault API server..."
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}🔐 PQC-ZTA Password Vault Backend${NC}"
echo -e "${BLUE}🔒 Quantum-Safe Cryptography Enabled${NC}"
echo -e "${BLUE}🛡️  Zero Trust Architecture Active${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""
echo -e "${GREEN}Server starting on: http://$HOST:$PORT${NC}"
echo -e "${GREEN}API Documentation: http://$HOST:$PORT/api/docs${NC}"
echo -e "${GREEN}Health Check: http://$HOST:$PORT/health${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Launch the application
python main.py --mode server --host "$HOST" --port "$PORT" --config "$CONFIG"
