#!/bin/bash

# PQC-ZTA Password Vault Frontend Launcher
set -e # Exit on any error

echo "🚀 Starting PQC-ZTA Password Vault Frontend..."
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

# Check if Node.js is installed
if ! command -v node &>/dev/null; then
    print_error "Node.js is required but not installed."
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Check Node.js version (16+)
node_version=$(node -v | sed 's/v//')
required_version="16.0.0"

if [ "$(printf '%s\n' "$required_version" "$node_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_error "Node.js 16+ is required. Current version: $node_version"
    exit 1
fi

print_status "Node.js $node_version detected ✓"

# Check if npm is installed
if ! command -v npm &>/dev/null; then
    print_error "npm is required but not installed."
    exit 1
fi

npm_version=$(npm -v)
print_status "npm $npm_version detected ✓"

# Navigate to frontend directory
if [ ! -d "frontend" ]; then
    print_error "Frontend directory not found."
    print_error "Please run this script from the project root directory."
    exit 1
fi

print_status "Navigating to frontend directory..."
cd frontend

# Check if package.json exists
if [ ! -f "package.json" ]; then
    print_error "package.json not found in frontend directory."
    exit 1
fi

# Check if node_modules exists and install dependencies
if [ ! -d "node_modules" ]; then
    print_status "Installing frontend dependencies..."
    npm install
    if [ $? -eq 0 ]; then
        print_status "Dependencies installed ✓"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
else
    print_status "Dependencies found, checking for updates..."
    npm ci --production=false
    if [ $? -eq 0 ]; then
        print_status "Dependencies updated ✓"
    else
        print_warning "Failed to update dependencies, continuing with existing ones..."
    fi
fi

# Check for Next.js configuration
if [ ! -f "next.config.ts" ] && [ ! -f "next.config.js" ]; then
    print_warning "No Next.js configuration found"
fi

# Parse command line arguments
PORT="${PORT:-3000}"
HOST="${HOST:-localhost}"

while [[ $# -gt 0 ]]; do
    case $1 in
    --port)
        PORT="$2"
        shift 2
        ;;
    --host)
        HOST="$2"
        shift 2
        ;;
    --build)
        print_status "Building production frontend..."
        npm run build
        exit 0
        ;;
    --production)
        print_status "Starting production server..."
        npm run start
        exit 0
        ;;
    -h | --help)
        echo "PQC-ZTA Password Vault Frontend Launcher"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --port PORT      Development server port (default: 3000)"
        echo "  --host HOST      Development server host (default: localhost)"
        echo "  --build          Build production version"
        echo "  --production     Start production server"
        echo "  -h, --help       Show this help message"
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

# Check backend connectivity
print_status "Checking backend connectivity..."
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"

if command -v curl &>/dev/null; then
    if curl -s "$BACKEND_URL/health" &>/dev/null; then
        print_status "Backend connection ✓"
    else
        print_warning "Backend not accessible at $BACKEND_URL"
        print_warning "Make sure the backend is running: ./run-backend.sh"
    fi
else
    print_warning "curl not available. Assuming backend is running."
fi

# Final status check
print_status "Configuration:"
echo "  Host: $HOST"
echo "  Port: $PORT"
echo "  Backend: $BACKEND_URL"
echo ""

# Set environment variables for the frontend
export NEXT_PUBLIC_API_URL="${BACKEND_URL}"
export PORT="$PORT"

# Start the development server
print_status "Starting PQC-ZTA Password Vault Frontend..."
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}🔐 PQC-ZTA Password Vault Frontend${NC}"
echo -e "${BLUE}🔒 Quantum-Safe Authentication UI${NC}"
echo -e "${BLUE}🛡️  Zero Trust Access Controls${NC}"
echo -e "${BLUE}==========================================${NC}"
echo ""
echo -e "${GREEN}Frontend starting on: http://$HOST:$PORT${NC}"
echo -e "${GREEN}API Backend: $BACKEND_URL${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""

# Launch the development server
npm run dev -- --port "$PORT" --hostname "$HOST"
