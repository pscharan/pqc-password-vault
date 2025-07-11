#!/bin/bash

# Script to run the application using Docker Compose
echo "PQ Password Manager - Docker Compose Runner"
echo "==========================================="

# Function to show usage
show_usage() {
    echo "Usage: $0 [dev|prod|stop|logs|clean]"
    echo ""
    echo "Commands:"
    echo "  dev    - Start development environment with hot reloading"
    echo "  prod   - Start production environment"
    echo "  stop   - Stop all services"
    echo "  logs   - Show logs from all services"
    echo "  clean  - Stop and remove all containers, volumes, and images"
    echo ""
    exit 1
}

# Check if Docker and Docker Compose are installed
check_docker() {
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker is not installed or not in PATH"
        echo "Please install Docker and try again"
        exit 1
    fi

    if ! command -v docker-compose &>/dev/null; then
        echo "Error: Docker Compose is not installed or not in PATH"
        echo "Please install Docker Compose and try again"
        exit 1
    fi
}

# Start development environment
start_dev() {
    echo "Starting development environment..."
    echo "Backend will be available at: http://localhost:8000"
    echo "Frontend will be available at: http://localhost:3000"
    echo "API Documentation at: http://localhost:8000/docs"
    echo ""
    docker-compose -f docker-compose.dev.yml up --build
}

# Start production environment
start_prod() {
    echo "Starting production environment..."
    echo "Backend will be available at: http://localhost:8000"
    echo "Frontend will be available at: http://localhost:3000"
    echo "API Documentation at: http://localhost:8000/docs"
    echo ""
    docker-compose up --build -d
    echo "Services started in detached mode"
    echo "Use './docker-run.sh logs' to view logs"
}

# Stop services
stop_services() {
    echo "Stopping all services..."
    docker-compose -f docker-compose.dev.yml down
    docker-compose down
    echo "All services stopped"
}

# Show logs
show_logs() {
    echo "Showing logs from all services..."
    echo "Press Ctrl+C to stop viewing logs"
    docker-compose logs -f
}

# Clean everything
clean_all() {
    echo "Warning: This will remove all containers, volumes, and images related to this project"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Cleaning up..."
        docker-compose -f docker-compose.dev.yml down -v --rmi all
        docker-compose down -v --rmi all
        docker system prune -f
        echo "Cleanup completed"
    else
        echo "Cleanup cancelled"
    fi
}

# Main script logic
check_docker

case "${1:-}" in
"dev")
    start_dev
    ;;
"prod")
    start_prod
    ;;
"stop")
    stop_services
    ;;
"logs")
    show_logs
    ;;
"clean")
    clean_all
    ;;
*)
    show_usage
    ;;
esac
