#!/bin/bash

# PQC-ZTA Password Vault Full-Stack Development Environment
set -e

echo "🚀 Starting PQC-ZTA Password Vault - Full Development Environment"
echo "🔒 Post-Quantum Cryptography enabled Zero Trust Architecture"
echo "=========================================="

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

# Check if required scripts exist and are executable
make_executable() {
    local script=$1
    if [ -f "$script" ]; then
        chmod +x "$script"
        print_status "$script made executable"
    else
        print_error "$script not found"
        exit 1
    fi
}

# Process IDs for cleanup
BACKEND_PID=""
FRONTEND_PID=""
DOCKER_STARTED=""

# Cleanup function
cleanup() {
    echo ""
    print_status "Shutting down development environment..."

    # Kill backend process
    if [ ! -z "$BACKEND_PID" ]; then
        print_status "Stopping backend server..."
        kill $BACKEND_PID 2>/dev/null || true
    fi

    # Kill frontend process
    if [ ! -z "$FRONTEND_PID" ]; then
        print_status "Stopping frontend server..."
        kill $FRONTEND_PID 2>/dev/null || true
    fi

    # Optional: Stop Docker services if we started them
    if [ "$DOCKER_STARTED" = "true" ]; then
        print_status "Stopping Docker services..."
        docker-compose down 2>/dev/null || true
    fi

    print_status "Development environment stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Parse command line arguments
SKIP_DOCKER=false
SKIP_TESTS=false
SERVICES_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
    --skip-docker)
        SKIP_DOCKER=true
        shift
        ;;
    --skip-tests)
        SKIP_TESTS=true
        shift
        ;;
    --services-only)
        SERVICES_ONLY=true
        shift
        ;;
    --help | -h)
        echo "PQC-ZTA Password Vault Development Environment"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --skip-docker     Skip Docker services startup"
        echo "  --skip-tests      Skip initial system tests"
        echo "  --services-only   Only start supporting services (DB, Redis, OPA)"
        echo "  -h, --help        Show this help message"
        echo ""
        echo "Environment:"
        echo "  Backend Server:   http://localhost:8000"
        echo "  Frontend App:     http://localhost:3000"
        echo "  API Docs:         http://localhost:8000/api/docs"
        echo "  Health Check:     http://localhost:8000/health"
        echo "  Dashboard:        http://localhost:8501 (if enabled)"
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

# Make scripts executable
print_status "Preparing launch scripts..."
make_executable "run-backend.sh"
make_executable "run-frontend.sh"
make_executable "setup.sh"

if [ -f "test-system.sh" ]; then
    make_executable "test-system.sh"
fi

# Run system tests first (unless skipped)
if [ "$SKIP_TESTS" = "false" ] && [ -f "test-system.sh" ]; then
    print_status "Running initial system tests..."
    if ./test-system.sh; then
        print_status "System tests passed ✓"
    else
        print_error "System tests failed. Please fix issues before continuing."
        exit 1
    fi
    echo ""
fi

# Start Docker services (unless skipped)
if [ "$SKIP_DOCKER" = "false" ]; then
    print_status "Checking Docker services..."

    if command -v docker-compose &>/dev/null || command -v docker &>/dev/null; then
        if docker-compose ps | grep -q "Up" 2>/dev/null; then
            print_status "Docker services already running ✓"
        else
            print_status "Starting Docker services (PostgreSQL, Redis, OPA)..."
            docker-compose up -d postgres redis opa
            DOCKER_STARTED=true

            # Wait for services to be ready
            print_status "Waiting for services to be ready..."
            sleep 5

            # Check PostgreSQL
            if docker-compose exec -T postgres pg_isready >/dev/null 2>&1; then
                print_status "PostgreSQL ready ✓"
            else
                print_warning "PostgreSQL may not be ready yet"
            fi

            # Check Redis
            if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
                print_status "Redis ready ✓"
            else
                print_warning "Redis may not be ready yet"
            fi
        fi
    else
        print_warning "Docker not available. Make sure services are running manually."
    fi
    echo ""
fi

# If services-only mode, start dashboard and exit
if [ "$SERVICES_ONLY" = "true" ]; then
    print_status "Starting Streamlit dashboard..."
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}📊 PQC-ZTA Dashboard Only Mode${NC}"
    echo -e "${BLUE}🔍 Real-time Monitoring Active${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo ""
    echo -e "${GREEN}Dashboard: http://localhost:8501${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""

    cd pass_vault
    python main.py --mode dashboard
    exit 0
fi

# Function to run backend in background
run_backend() {
    print_status "Starting backend server..."
    ./run-backend.sh &
    BACKEND_PID=$!

    # Wait a moment and check if it's still running
    sleep 3
    if kill -0 $BACKEND_PID 2>/dev/null; then
        print_status "Backend server started successfully (PID: $BACKEND_PID)"
    else
        print_error "Backend server failed to start"
        exit 1
    fi
}

# Function to run frontend in background
run_frontend() {
    print_status "Starting frontend server..."
    ./run-frontend.sh &
    FRONTEND_PID=$!

    # Wait a moment and check if it's still running
    sleep 3
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        print_status "Frontend server started successfully (PID: $FRONTEND_PID)"
    else
        print_error "Frontend server failed to start"
        exit 1
    fi
}

# Start backend server
print_status "Launching backend server..."
run_backend
echo ""

# Wait for backend to be ready
print_status "Waiting for backend to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        print_status "Backend health check passed ✓"
        break
    fi
    if [ $i -eq 30 ]; then
        print_warning "Backend health check timed out"
    fi
    sleep 1
done

# Start frontend server
print_status "Launching frontend server..."
run_frontend
echo ""

# Display service information
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}🔐 PQC-ZTA Password Vault Development${NC}"
echo -e "${BLUE}🔒 Quantum-Safe Cryptography Active${NC}"
echo -e "${BLUE}🛡️  Zero Trust Architecture Enabled${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""
echo -e "${GREEN}🚀 Services Running:${NC}"
echo -e "   Backend API:      ${GREEN}http://localhost:8000${NC}"
echo -e "   Frontend App:     ${GREEN}http://localhost:3000${NC}"
echo -e "   API Docs:         ${GREEN}http://localhost:8000/api/docs${NC}"
echo -e "   Health Check:     ${GREEN}http://localhost:8000/health${NC}"
echo ""
echo -e "${YELLOW}📊 Optional Services:${NC}"
echo -e "   Dashboard:        ${YELLOW}http://localhost:8501${NC} (run: python pass_vault/main.py --mode dashboard)"
echo -e "   Grafana:          ${YELLOW}http://localhost:3001${NC} (if enabled)"
echo -e "   Prometheus:       ${YELLOW}http://localhost:9090${NC} (if enabled)"
echo ""
echo -e "${BLUE}💾 Database Services:${NC}"
if [ "$SKIP_DOCKER" = "false" ]; then
    echo -e "   PostgreSQL:       ${GREEN}localhost:5432${NC}"
    echo -e "   Redis:            ${GREEN}localhost:6379${NC}"
    echo -e "   OPA:              ${GREEN}localhost:8181${NC}"
else
    echo -e "   PostgreSQL:       ${YELLOW}Configure manually${NC}"
    echo -e "   Redis:            ${YELLOW}Configure manually${NC}"
    echo -e "   OPA:              ${YELLOW}Configure manually${NC}"
fi
echo ""
echo -e "${RED}Press Ctrl+C to stop all services${NC}"
echo ""

# Monitor both processes
while true; do
    # Check if backend is still running
    if [ ! -z "$BACKEND_PID" ] && ! kill -0 $BACKEND_PID 2>/dev/null; then
        print_error "Backend server stopped unexpectedly"
        cleanup
    fi

    # Check if frontend is still running
    if [ ! -z "$FRONTEND_PID" ] && ! kill -0 $FRONTEND_PID 2>/dev/null; then
        print_error "Frontend server stopped unexpectedly"
        cleanup
    fi

    sleep 5
done
