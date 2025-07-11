# PQ Password Manager - Deployment Guide

This guide explains how to run the PQ Password Manager application using different methods.

## Prerequisites

### For Local Development
- Python 3.11+
- Node.js 18+
- npm or yarn

### For Docker Deployment
- Docker
- Docker Compose

## Quick Start

### Option 1: Local Development (Recommended for development)

1. **Run both services together:**
   ```bash
   ./run-dev.sh
   ```

2. **Run services separately:**
   ```bash
   # Terminal 1 - Backend
   ./run-backend.sh
   
   # Terminal 2 - Frontend
   ./run-frontend.sh
   ```

### Option 2: Docker Compose (Recommended for production)

1. **Development environment with hot reloading:**
   ```bash
   ./docker-run.sh dev
   ```

2. **Production environment:**
   ```bash
   ./docker-run.sh prod
   ```

3. **Stop all services:**
   ```bash
   ./docker-run.sh stop
   ```

4. **View logs:**
   ```bash
   ./docker-run.sh logs
   ```

5. **Clean up everything:**
   ```bash
   ./docker-run.sh clean
   ```

## Service URLs

Once running, you can access:

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **API Redoc**: http://localhost:8000/redoc

## Manual Setup

### Backend Setup

1. Create virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r pass_vault/requirements.txt
   ```

3. Set Python path:
   ```bash
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

4. Run the server:
   ```bash
   cd pass_vault
   python main.py --mode server --host 0.0.0.0 --port 8000
   ```

### Frontend Setup

1. Navigate to frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run development server:
   ```bash
   npm run dev
   ```

4. Build for production:
   ```bash
   npm run build
   npm start
   ```

## Docker Configuration

### Development vs Production

- **Development (`docker-compose.dev.yml`)**:
  - Hot reloading enabled
  - Volume mounts for live code changes
  - Development optimizations
  - Verbose logging

- **Production (`docker-compose.yml`)**:
  - Optimized builds
  - Health checks
  - Restart policies
  - Optional nginx reverse proxy

### Environment Variables

Create a `.env` file in the root directory:

```env
# Backend Configuration
PYTHONPATH=/app
PYTHONUNBUFFERED=1
FASTAPI_ENV=production

# Frontend Configuration
NODE_ENV=production
NEXT_PUBLIC_API_URL=http://localhost:8000

# Database (if using external database)
# DATABASE_URL=postgresql://user:pass@localhost:5432/passdb
```

## Troubleshooting

### Common Issues

1. **Port already in use**:
   ```bash
   # Find process using port 8000 or 3000
   lsof -i :8000
   lsof -i :3000
   
   # Kill the process
   kill -9 <PID>
   ```

2. **Permission denied on scripts**:
   ```bash
   chmod +x *.sh
   ```

3. **Docker build fails**:
   ```bash
   # Clean Docker cache
   docker system prune -a
   
   # Rebuild without cache
   docker-compose build --no-cache
   ```

4. **Backend import errors**:
   ```bash
   # Ensure PYTHONPATH is set correctly
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

### Health Checks

- Backend health: `curl http://localhost:8000/`
- Frontend health: `curl http://localhost:3000/`

### Logs

- **Local development**: Check terminal output
- **Docker**: `./docker-run.sh logs` or `docker-compose logs -f`

## Production Deployment

For production deployment, consider:

1. **Environment Variables**: Set proper production values
2. **SSL/TLS**: Configure HTTPS (nginx service included)
3. **Database**: Use external database instead of SQLite
4. **Monitoring**: Add logging and monitoring solutions
5. **Backup**: Implement backup strategies
6. **Security**: Review security configurations

### Nginx Configuration (Optional)

The production Docker Compose includes an optional nginx service for reverse proxy. To enable:

```bash
# Start with nginx profile
docker-compose --profile production up -d
```

Create `nginx.conf` and SSL certificates as needed.

## Development Tips

1. **API Testing**: Use the built-in documentation at `/docs`
2. **Hot Reloading**: Use development mode for live code changes
3. **Debug Mode**: Set `FASTAPI_ENV=development` for detailed error messages
4. **Database**: Check the backend data volume for persistent storage

## Support

For issues and questions:
1. Check the logs for error messages
2. Ensure all prerequisites are installed
3. Verify network connectivity between services
4. Check Docker/container status if using Docker 