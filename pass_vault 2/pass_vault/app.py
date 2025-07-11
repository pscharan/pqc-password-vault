from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sys
import logging
from datetime import datetime
import structlog
from werkzeug.middleware.proxy_fix import ProxyFix

# Import our API routes
from api.routes import api_bp, init_app_with_routes
from api.auth import auth_bp
from storage.vault import EnhancedVaultManager

def create_app(config_name='production'):
    """Application factory pattern for Flask app creation."""
    
    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Create Flask application
    app = Flask(__name__)
    
    # Configure application
    app.config.update({
        'SECRET_KEY': os.getenv('SECRET_KEY', 'dev-secret-change-in-production'),
        'DATABASE_URL': os.getenv('DATABASE_URL', 'postgresql://vault_user:vault_password@localhost:5432/vault_db'),
        'REDIS_URL': os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        'OPA_URL': os.getenv('OPA_URL', 'http://localhost:8181'),
        'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', app.config['SECRET_KEY']),
        'JWT_ACCESS_TOKEN_EXPIRES': int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600')),
        'WEBAUTHN_RP_ID': os.getenv('WEBAUTHN_RP_ID', 'localhost'),
        'WEBAUTHN_RP_NAME': os.getenv('WEBAUTHN_RP_NAME', 'PQC-ZTA Password Vault'),
        'WEBAUTHN_ORIGIN': os.getenv('WEBAUTHN_ORIGIN', 'http://localhost:3000'),
        'PQC_AUDIT_LOG_PATH': os.getenv('PQC_AUDIT_LOG_PATH', './logs/pqc_audit.log'),
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max request size
        'JSON_SORT_KEYS': False,
        'JSONIFY_PRETTYPRINT_REGULAR': False,
    })
    
    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
    
    # Configure CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                os.getenv('FRONTEND_URL', 'http://localhost:3000')
            ],
            "allow_headers": [
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "X-Device-ID",
                "X-Request-ID"
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "supports_credentials": True
        }
    })
    
    # Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per hour"],
        storage_uri=app.config['REDIS_URL']
    )
    
    # Proxy fix for correct client IP when behind reverse proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Configure logging
    if config_name == 'production':
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
        app.config['DEBUG'] = True
    
    logger = structlog.get_logger(__name__)
    
    # Initialize vault manager
    try:
        vault_manager = EnhancedVaultManager(app.config['DATABASE_URL'])
        app.vault_manager = vault_manager
        logger.info("Vault manager initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize vault manager", error=str(e))
        sys.exit(1)
    
    # Initialize application with routes
    init_app_with_routes(app)
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    # Root endpoint
    @app.route('/')
    def root():
        """Root endpoint with API information."""
        return jsonify({
            "message": "PQC-ZTA Password Vault API",
            "version": "1.0.0",
            "features": [
                "Post-Quantum Cryptography (Kyber, Dilithium, SPHINCS+)",
                "Zero Trust Architecture with OPA",
                "WebAuthn/FIDO2 Biometric Authentication",
                "GDPR-Compliant Audit Logging",
                "Real-time Risk Assessment"
            ],
            "endpoints": {
                "docs": "/api/docs",
                "health": "/api/v1/health",
                "auth": "/api/auth/",
                "vault": "/api/v1/vault/"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        try:
            # Test database connection
            vault_manager.db.execute("SELECT 1")
            db_status = "healthy"
        except Exception:
            db_status = "unhealthy"
        
        return jsonify({
            "status": "healthy" if db_status == "healthy" else "degraded",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "components": {
                "database": db_status,
                "pqc": "enabled",
                "zta": "enabled"
            }
        })
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "success": False,
            "error": "Bad request",
            "message": "The request could not be understood by the server"
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "success": False,
            "error": "Unauthorized",
            "message": "Authentication required"
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "success": False,
            "error": "Forbidden",
            "message": "Access denied by Zero Trust policy"
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Not found",
            "message": "The requested resource was not found"
        }), 404
    
    @app.errorhandler(429)
    def ratelimit_handler(error):
        return jsonify({
            "success": False,
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later."
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Internal server error", error=str(error))
        return jsonify({
            "success": False,
            "error": "Internal server error",
            "message": "An unexpected error occurred"
        }), 500
    
    # Request logging middleware
    @app.before_request
    def log_request_info():
        logger.info(
            "Request received",
            method=request.method,
            path=request.path,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown')
        )
    
    logger.info("Flask application created successfully", config=config_name)
    return app

def run_server():
    """Run the Flask development server."""
    app = create_app('development')
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 8000))
    
    print(f"🚀 Starting PQC-ZTA Password Vault API server on {host}:{port}")
    print(f"📚 API Documentation: http://{host}:{port}/api/docs")
    print(f"❤️  Health Check: http://{host}:{port}/health")
    
    app.run(
        host=host,
        port=port,
        debug=True,
        threaded=True
    )

if __name__ == "__main__":
    run_server() 