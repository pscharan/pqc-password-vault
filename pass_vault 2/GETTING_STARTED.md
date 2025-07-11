# Getting Started with PQC-ZTA Password Vault

🔒 **Post-Quantum Cryptography enabled Zero Trust Architecture Password Vault**

This guide will help you set up and run the PQC-ZTA Password Vault system on your local machine.

## 🎯 Overview

The PQC-ZTA Password Vault is a cutting-edge password management system that combines:

- **Post-Quantum Cryptography (PQC)**: Kyber-1024, Dilithium-III, and SPHINCS+ algorithms
- **Zero Trust Architecture (ZTA)**: Continuous verification with Open Policy Agent (OPA)
- **WebAuthn/FIDO2**: Biometric authentication support
- **Real-time Monitoring**: Streamlit dashboard with risk assessment
- **GDPR Compliance**: Privacy-by-design with cryptographic audit trails

## 📋 Prerequisites

### System Requirements
- **Operating System**: macOS, Linux, or Windows (with WSL)
- **Python**: 3.8 or higher
- **Node.js**: 16.0 or higher
- **Docker**: Latest version with Docker Compose
- **Memory**: At least 4GB RAM
- **Storage**: At least 2GB free space

### Required Software

1. **Python 3.8+**
   ```bash
   # Check version
   python3 --version
   ```

2. **Node.js 16+**
   ```bash
   # Check version
   node --version
   npm --version
   ```

3. **Docker & Docker Compose**
   ```bash
   # Check Docker
   docker --version
   docker-compose --version
   ```

## 🚀 Quick Start

### Step 1: Clone and Setup

```bash
# Navigate to your development directory
cd ~/Documents/APPS/pass_vault

# Run system tests to verify everything is ready
chmod +x test-system.sh
./test-system.sh
```

### Step 2: Configure Environment

```bash
# Create environment configuration
cp pass_vault/config.template pass_vault/.env

# Edit configuration (see Configuration section below)
nano pass_vault/.env  # or use your preferred editor
```

### Step 3: Start the System

**Option A: Full Development Environment (Recommended)**
```bash
# Start all services (backend, frontend, database, etc.)
chmod +x run-dev.sh
./run-dev.sh
```

**Option B: Individual Components**
```bash
# Start supporting services first
./setup.sh

# Start backend in one terminal
./run-backend.sh

# Start frontend in another terminal
./run-frontend.sh
```

### Step 4: Access the Application

Once everything is running, you can access:

- **Frontend Application**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/health
- **Dashboard** (optional): http://localhost:8501

## ⚙️ Configuration

### Environment Variables

Edit `pass_vault/.env` with your settings:

```env
# Core Application
SECRET_KEY=your-super-secret-key-change-this-in-production
DATABASE_URL=postgresql://vault_user:vault_password@localhost:5432/vault_db
REDIS_URL=redis://localhost:6379/0

# Authentication
JWT_SECRET_KEY=your-jwt-secret-key-change-this
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=PQC-ZTA Password Vault
WEBAUTHN_ORIGIN=http://localhost:3000

# Zero Trust
OPA_URL=http://localhost:8181
RISK_THRESHOLD_LOW=0.3
RISK_THRESHOLD_MEDIUM=0.6
RISK_THRESHOLD_HIGH=0.8
```

### Database Configuration

The system uses PostgreSQL with the following default settings:
- **Host**: localhost
- **Port**: 5432
- **Database**: vault_db
- **Username**: vault_user
- **Password**: vault_password

### Security Configuration

For production use, ensure you:
1. Change all default passwords
2. Use strong, unique secret keys
3. Configure proper SSL/TLS certificates
4. Set up proper firewall rules
5. Enable audit logging

## 🛠️ Development Commands

### Backend Commands

```bash
# Start backend only
./run-backend.sh

# Start with custom configuration
./run-backend.sh --config production --port 8080

# Run setup and migrations
./run-backend.sh --setup

# Start dashboard mode
./run-backend.sh --dashboard
```

### Frontend Commands

```bash
# Start frontend only
./run-frontend.sh

# Build production version
./run-frontend.sh --build

# Start production server
./run-frontend.sh --production
```

### Development Environment

```bash
# Full development environment
./run-dev.sh

# Skip Docker services (if running manually)
./run-dev.sh --skip-docker

# Skip system tests
./run-dev.sh --skip-tests

# Services only (database, Redis, OPA)
./run-dev.sh --services-only
```

### Testing

```bash
# Run comprehensive system tests
./test-system.sh

# Test specific components
cd pass_vault
python -m pytest tests/

# Test PQC functionality
python test_symmetric_crypto.py
```

## 🐳 Docker Services

The system includes the following Docker services:

### Core Services
- **PostgreSQL**: Database with PQC extensions
- **Redis**: Session storage and caching
- **Open Policy Agent (OPA)**: Zero Trust policy enforcement

### Optional Services
- **Prometheus**: Metrics collection
- **Grafana**: Monitoring dashboard
- **Streamlit**: Real-time vault dashboard

### Docker Commands

```bash
# Start all services
docker-compose up -d

# Start specific services
docker-compose up -d postgres redis opa

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Reset everything
docker-compose down -v
docker-compose up -d
```

## 🔐 Security Features

### Post-Quantum Cryptography
- **Kyber-1024**: Key encapsulation mechanism
- **Dilithium-III**: Digital signatures
- **SPHINCS+**: Hash-based signatures for audit logs

### Zero Trust Architecture
- Continuous verification of all requests
- Risk-based access control
- Device context evaluation
- Geographic and time-based restrictions

### WebAuthn/FIDO2
- Platform authenticators (Touch ID, Face ID, Windows Hello)
- Cross-platform authenticators (YubiKey, etc.)
- Step-up authentication for sensitive operations

### Audit & Compliance
- Cryptographically signed audit trails
- GDPR-compliant data handling
- Real-time anomaly detection
- Privacy-by-design architecture

## 📊 Monitoring & Dashboards

### Streamlit Dashboard
Access real-time monitoring at http://localhost:8501

Features:
- Live vault statistics
- Risk assessment metrics
- Audit log analysis
- Performance monitoring

### API Monitoring
- Health check endpoint: `/health`
- Metrics endpoint: `/api/v1/metrics`
- Audit logs: `/api/v1/audit`

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using the port
   lsof -i :8000
   
   # Use different port
   ./run-backend.sh --port 8080
   ```

2. **Database Connection Failed**
   ```bash
   # Check if PostgreSQL is running
   docker-compose ps postgres
   
   # View PostgreSQL logs
   docker-compose logs postgres
   ```

3. **Dependencies Not Found**
   ```bash
   # Reinstall Python dependencies
   pip install -r pass_vault/requirements.txt
   
   # Reinstall Node.js dependencies
   cd frontend && npm install
   ```

4. **Permission Denied on Scripts**
   ```bash
   # Make scripts executable
   chmod +x *.sh
   ```

### Getting Help

1. **System Tests**: Run `./test-system.sh` to diagnose issues
2. **Check Logs**: View application logs in the `logs/` directory
3. **Health Check**: Visit http://localhost:8000/health
4. **Docker Status**: Run `docker-compose ps` to check service status

## 🔧 Advanced Configuration

### Custom Database
```env
DATABASE_URL=postgresql://user:pass@host:port/dbname
```

### Custom Redis
```env
REDIS_URL=redis://host:port/db
```

### External OPA
```env
OPA_URL=http://your-opa-server:8181
```

### Production Settings
```env
FLASK_ENV=production
DEBUG=false
RATE_LIMIT_ENABLED=true
SECURITY_HEADERS_ENABLED=true
```

## 📚 Next Steps

1. **Explore the API**: Visit http://localhost:8000/api/docs
2. **Set up WebAuthn**: Configure biometric authentication
3. **Customize Policies**: Edit OPA policies in `opa-policies/`
4. **Monitor Usage**: Check the Streamlit dashboard
5. **Review Logs**: Examine audit trails and security events

## 🤝 Support

- **Documentation**: See `COMPREHENSIVE_DOCUMENTATION.md`
- **Deployment**: See `DEPLOYMENT.md`
- **Architecture**: Review the project details and design documents

---

**Security Notice**: This system implements experimental post-quantum cryptography. While based on NIST standards, thoroughly evaluate security implications before production use. 