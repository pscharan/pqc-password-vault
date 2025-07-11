#!/bin/bash

# PQC-ZTA Password Vault System Test Script
set -e

echo "🧪 PQC-ZTA Password Vault System Tests"
echo "🔒 Testing Post-Quantum Cryptography and Zero Trust Architecture"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

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

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Test result functions
test_passed() {
    echo -e "${GREEN}✓ PASSED${NC} $1"
    ((TESTS_PASSED++))
    ((TOTAL_TESTS++))
}

test_failed() {
    echo -e "${RED}✗ FAILED${NC} $1"
    ((TESTS_FAILED++))
    ((TOTAL_TESTS++))
}

# Test functions
test_dependencies() {
    print_test "Testing system dependencies..."

    # Python 3.8+
    if command -v python3 &>/dev/null; then
        python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if [ "$(printf '%s\n' "3.8" "$python_version" | sort -V | head -n1)" == "3.8" ]; then
            test_passed "Python $python_version installed"
        else
            test_failed "Python 3.8+ required, found $python_version"
        fi
    else
        test_failed "Python 3 not found"
    fi

    # Node.js 16+
    if command -v node &>/dev/null; then
        node_version=$(node -v | sed 's/v//')
        if [ "$(printf '%s\n' "16.0.0" "$node_version" | sort -V | head -n1)" == "16.0.0" ]; then
            test_passed "Node.js $node_version installed"
        else
            test_failed "Node.js 16+ required, found $node_version"
        fi
    else
        test_failed "Node.js not found"
    fi

    # Docker
    if command -v docker &>/dev/null; then
        test_passed "Docker installed"
    else
        test_failed "Docker not found"
    fi

    # Docker Compose
    if command -v docker-compose &>/dev/null || docker compose version &>/dev/null; then
        test_passed "Docker Compose available"
    else
        test_failed "Docker Compose not found"
    fi
}

test_python_dependencies() {
    print_test "Testing Python dependencies..."

    cd pass_vault

    # Test virtual environment
    if [ -d "../venv" ]; then
        source ../venv/bin/activate
        test_passed "Virtual environment activated"
    else
        test_failed "Virtual environment not found"
        return
    fi

    # Test key imports
    python3 -c "import flask" 2>/dev/null && test_passed "Flask import" || test_failed "Flask import"
    python3 -c "import sqlalchemy" 2>/dev/null && test_passed "SQLAlchemy import" || test_failed "SQLAlchemy import"
    python3 -c "import structlog" 2>/dev/null && test_passed "Structlog import" || test_failed "Structlog import"
    python3 -c "import redis" 2>/dev/null && test_passed "Redis import" || test_failed "Redis import"
    python3 -c "import cryptography" 2>/dev/null && test_passed "Cryptography import" || test_failed "Cryptography import"

    # Test PQC imports
    python3 -c "from crypto.pqc import PQCKeyManager" 2>/dev/null && test_passed "PQC modules import" || test_failed "PQC modules import"
    python3 -c "from crypto.symmetric import generate_aes_key" 2>/dev/null && test_passed "Symmetric crypto import" || test_failed "Symmetric crypto import"

    # Test ZTA imports
    python3 -c "from auth.zta import ZTAManager" 2>/dev/null && test_passed "ZTA modules import" || test_failed "ZTA modules import"

    # Test WebAuthn imports
    python3 -c "from auth.webauthn import WebAuthnManager" 2>/dev/null && test_passed "WebAuthn modules import" || test_failed "WebAuthn modules import"

    cd ..
}

test_database_schema() {
    print_test "Testing database schema..."

    cd pass_vault

    # Test Alembic configuration
    if [ -f "alembic.ini" ]; then
        test_passed "Alembic configuration found"
    else
        test_failed "Alembic configuration missing"
    fi

    # Test migration files
    if [ -f "alembic/versions/001_initial_pqc_zta_schema.py" ]; then
        test_passed "Initial migration found"
    else
        test_failed "Initial migration missing"
    fi

    cd ..
}

test_configuration() {
    print_test "Testing configuration files..."

    # Test configuration template
    if [ -f "pass_vault/config.template" ]; then
        test_passed "Configuration template found"
    else
        test_failed "Configuration template missing"
    fi

    # Test Docker configuration
    if [ -f "docker-compose.yml" ]; then
        test_passed "Docker Compose configuration found"
    else
        test_failed "Docker Compose configuration missing"
    fi

    # Test OPA policies
    if [ -f "opa-policies/vault_access.rego" ]; then
        test_passed "OPA policies found"
    else
        test_failed "OPA policies missing"
    fi

    # Test database initialization
    if [ -f "init-db.sql" ]; then
        test_passed "Database initialization script found"
    else
        test_failed "Database initialization script missing"
    fi
}

test_application_structure() {
    print_test "Testing application structure..."

    # Test main entry points
    if [ -f "pass_vault/main.py" ]; then
        test_passed "Main application entry point found"
    else
        test_failed "Main application entry point missing"
    fi

    if [ -f "pass_vault/app.py" ]; then
        test_passed "Flask application found"
    else
        test_failed "Flask application missing"
    fi

    # Test API structure
    if [ -f "pass_vault/api/routes.py" ]; then
        test_passed "API routes found"
    else
        test_failed "API routes missing"
    fi

    if [ -f "pass_vault/api/auth.py" ]; then
        test_passed "API authentication found"
    else
        test_failed "API authentication missing"
    fi

    if [ -f "pass_vault/api/models.py" ]; then
        test_passed "API models found"
    else
        test_failed "API models missing"
    fi

    # Test core modules
    if [ -f "pass_vault/storage/vault.py" ]; then
        test_passed "Vault storage module found"
    else
        test_failed "Vault storage module missing"
    fi

    if [ -f "pass_vault/crypto/pqc.py" ]; then
        test_passed "PQC module found"
    else
        test_failed "PQC module missing"
    fi

    if [ -f "pass_vault/auth/zta.py" ]; then
        test_passed "ZTA module found"
    else
        test_failed "ZTA module missing"
    fi

    if [ -f "pass_vault/auth/webauthn.py" ]; then
        test_passed "WebAuthn module found"
    else
        test_failed "WebAuthn module missing"
    fi
}

test_frontend_structure() {
    print_test "Testing frontend structure..."

    # Test frontend directory
    if [ -d "frontend" ]; then
        test_passed "Frontend directory found"
    else
        test_failed "Frontend directory missing"
        return
    fi

    # Test package.json
    if [ -f "frontend/package.json" ]; then
        test_passed "Frontend package.json found"
    else
        test_failed "Frontend package.json missing"
    fi

    # Test Next.js configuration
    if [ -f "frontend/next.config.ts" ]; then
        test_passed "Next.js configuration found"
    else
        test_failed "Next.js configuration missing"
    fi

    # Test source structure
    if [ -d "frontend/src" ]; then
        test_passed "Frontend source directory found"
    else
        test_failed "Frontend source directory missing"
    fi
}

test_launch_scripts() {
    print_test "Testing launch scripts..."

    # Test backend script
    if [ -f "run-backend.sh" ] && [ -x "run-backend.sh" ]; then
        test_passed "Backend launch script found and executable"
    else
        test_failed "Backend launch script missing or not executable"
    fi

    # Test frontend script
    if [ -f "run-frontend.sh" ] && [ -x "run-frontend.sh" ]; then
        test_passed "Frontend launch script found and executable"
    else
        test_failed "Frontend launch script missing or not executable"
    fi

    # Test development script
    if [ -f "run-dev.sh" ] && [ -x "run-dev.sh" ]; then
        test_passed "Development launch script found and executable"
    else
        test_failed "Development launch script missing or not executable"
    fi

    # Test setup script
    if [ -f "setup.sh" ] && [ -x "setup.sh" ]; then
        test_passed "Setup script found and executable"
    else
        test_failed "Setup script missing or not executable"
    fi
}

test_syntax() {
    print_test "Testing Python syntax..."

    cd pass_vault

    if [ -d "../venv" ]; then
        source ../venv/bin/activate
    fi

    # Test main modules
    python3 -m py_compile main.py 2>/dev/null && test_passed "main.py syntax" || test_failed "main.py syntax"
    python3 -m py_compile app.py 2>/dev/null && test_passed "app.py syntax" || test_failed "app.py syntax"

    # Test API modules
    python3 -m py_compile api/routes.py 2>/dev/null && test_passed "routes.py syntax" || test_failed "routes.py syntax"
    python3 -m py_compile api/auth.py 2>/dev/null && test_passed "auth.py syntax" || test_failed "auth.py syntax"
    python3 -m py_compile api/models.py 2>/dev/null && test_passed "models.py syntax" || test_failed "models.py syntax"

    # Test core modules
    python3 -m py_compile storage/vault.py 2>/dev/null && test_passed "vault.py syntax" || test_failed "vault.py syntax"
    python3 -m py_compile crypto/pqc.py 2>/dev/null && test_passed "pqc.py syntax" || test_failed "pqc.py syntax"
    python3 -m py_compile auth/zta.py 2>/dev/null && test_passed "zta.py syntax" || test_failed "zta.py syntax"
    python3 -m py_compile auth/webauthn.py 2>/dev/null && test_passed "webauthn.py syntax" || test_failed "webauthn.py syntax"

    cd ..
}

# Run all tests
echo "Starting comprehensive system tests..."
echo ""

test_dependencies
echo ""

test_python_dependencies
echo ""

test_database_schema
echo ""

test_configuration
echo ""

test_application_structure
echo ""

test_frontend_structure
echo ""

test_launch_scripts
echo ""

test_syntax
echo ""

# Summary
echo "=========================================="
echo -e "${BLUE}TEST SUMMARY${NC}"
echo "=========================================="
echo -e "Total Tests: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 All tests passed! The system is ready to run.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Configure your environment: cp pass_vault/config.template pass_vault/.env"
    echo "2. Edit pass_vault/.env with your settings"
    echo "3. Start services: ./setup.sh"
    echo "4. Run backend: ./run-backend.sh"
    echo "5. Run frontend: ./run-frontend.sh"
    exit 0
else
    echo ""
    echo -e "${RED}❌ Some tests failed. Please fix the issues before running the system.${NC}"
    exit 1
fi
