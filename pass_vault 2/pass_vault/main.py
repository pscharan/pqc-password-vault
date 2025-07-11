# Main entry point for the PQC-ZTA Password Vault application
import sys
import argparse
import os
from pathlib import Path

def main():
    """
    Main function to run the PQC-ZTA password vault.
    Supports both CLI mode and web server mode.
    """
    parser = argparse.ArgumentParser(
        description="PQC-ZTA Password Vault - Post-Quantum Cryptography enabled Zero Trust Architecture password manager"
    )
    parser.add_argument(
        "--mode", 
        choices=["cli", "server", "dashboard"], 
        default="server",
        help="Run mode: CLI interface, web server, or dashboard (default: server)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for web server (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for web server (default: 8000)"
    )
    parser.add_argument(
        "--config",
        choices=["development", "production"],
        default="development",
        help="Configuration mode (default: development)"
    )
    parser.add_argument(
        "--db-url",
        help="Database URL (overrides environment variable)"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run initial setup and database migrations"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="PQC-ZTA Password Vault v1.0.0"
    )
    
    args = parser.parse_args()
    
    # Set environment variables if provided
    if args.db_url:
        os.environ['DATABASE_URL'] = args.db_url
    
    if args.host:
        os.environ['HOST'] = args.host
        
    if args.port:
        os.environ['PORT'] = str(args.port)
    
    # Run setup if requested
    if args.setup:
        print("🔧 Running initial setup...")
        try:
            from storage.vault import EnhancedVaultManager
            import subprocess
            
            # Run database migrations
            print("📊 Running database migrations...")
            result = subprocess.run(['alembic', 'upgrade', 'head'], 
                                  capture_output=True, text=True, cwd=Path(__file__).parent)
            
            if result.returncode == 0:
                print("✅ Database migrations completed successfully")
            else:
                print(f"❌ Database migration failed: {result.stderr}")
                sys.exit(1)
                
            print("✅ Setup completed successfully!")
            
        except ImportError as e:
            print(f"❌ Setup failed - missing dependencies: {e}")
            print("Please install requirements: pip install -r requirements.txt")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Setup failed: {e}")
            sys.exit(1)
        
        return
    
    if args.mode == "cli":
        # CLI Mode
        try:
            from cli.interface import main_cli
            print("🔐 PQC-ZTA Password Vault - CLI Mode")
            print("Post-Quantum Cryptography enabled Zero Trust Architecture")
            main_cli()
        except ImportError:
            print("❌ Error: Could not import CLI module.")
            print("Please ensure the CLI module is correctly structured and accessible.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ CLI Error: {e}")
            sys.exit(1)
    
    elif args.mode == "server":
        # Web Server Mode
        try:
            from app import create_app
            
            print("🚀 Starting PQC-ZTA Password Vault API Server")
            print(f"🔒 Post-Quantum Cryptography: Kyber, Dilithium, SPHINCS+")
            print(f"🛡️  Zero Trust Architecture: Continuous verification enabled")
            print(f"🖥️  Server: http://{args.host}:{args.port}")
            print(f"📚 API Docs: http://{args.host}:{args.port}/api/docs")
            print(f"❤️  Health Check: http://{args.host}:{args.port}/health")
            
            app = create_app(args.config)
            app.run(
                host=args.host,
                port=args.port,
                debug=(args.config == 'development'),
                threaded=True
            )
        except ImportError as e:
            print("❌ Error: Could not import web server dependencies.")
            print(f"Missing dependency: {e}")
            print("Please install requirements: pip install -r requirements.txt")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error starting web server: {e}")
            sys.exit(1)
    
    elif args.mode == "dashboard":
        # Dashboard Mode
        try:
            import subprocess
            import sys
            
            print("📊 Starting PQC-ZTA Dashboard...")
            print("🔍 Real-time monitoring and analytics")
            
            # Start Streamlit dashboard
            dashboard_path = Path(__file__).parent / "dashboard" / "streamlit_app.py"
            
            if not dashboard_path.exists():
                print(f"❌ Dashboard not found at {dashboard_path}")
                sys.exit(1)
            
            subprocess.run([
                sys.executable, "-m", "streamlit", "run", 
                str(dashboard_path),
                "--server.port", "8501",
                "--server.address", "0.0.0.0"
            ])
            
        except ImportError:
            print("❌ Error: Streamlit not installed.")
            print("Please install streamlit: pip install streamlit")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Dashboard Error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
