# PQ Password Manager

A secure post-quantum cryptography enabled password manager with a modern web interface. Built with Python FastAPI backend and Next.js frontend.

## Features

### 🔒 Security
- **Post-Quantum Cryptography**: Future-proof encryption resistant to quantum computing attacks
- **AES-256 Encryption**: Military-grade symmetric encryption for password storage
- **Zero-Knowledge Architecture**: Your master password never leaves your device
- **Argon2 Key Derivation**: Secure password hashing with salt
- **JWT Session Management**: Secure authentication tokens

### 💼 Password Management
- **Secure Vault Storage**: Encrypted SQLite database
- **Password Generation**: Customizable strong password generator
- **Search & Organization**: Quick search with tags and categories
- **Password Strength Validation**: Real-time password strength feedback
- **Secure Copy-to-Clipboard**: Safe password retrieval
- **Auto-lock Sessions**: Configurable session timeouts

### 🖥️ User Interface
- **Modern Dark Theme**: Beautiful gradient interface
- **Responsive Design**: Works on desktop and mobile
- **ShadCN UI Components**: Polished, accessible components
- **Real-time Updates**: Instant feedback and notifications
- **Intuitive Navigation**: Easy-to-use interface

## Project Structure

```
pass/
├── pass_vault/           # Python Backend
│   ├── api/             # FastAPI routes and models
│   ├── auth/            # Authentication & ZTA
│   ├── crypto/          # Cryptography modules
│   ├── storage/         # Database and vault operations
│   ├── cli/             # Command-line interface
│   ├── app.py           # FastAPI application
│   ├── main.py          # Entry point
│   └── requirements.txt # Python dependencies
│
└── frontend/            # Next.js Frontend
    ├── src/
    │   ├── app/         # Next.js app directory
    │   ├── components/  # UI components
    │   └── lib/         # API utilities
    ├── package.json     # Node.js dependencies
    └── .env.local       # Environment variables
```

## Setup Instructions

### Prerequisites
- Python 3.8+
- Node.js 18+
- npm or yarn

### Backend Setup

1. **Navigate to the backend directory:**
   ```bash
   cd pass_vault
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the backend server:**
   ```bash
   python main.py --mode server
   ```
   
   The API will be available at `http://localhost:8000`
   - API Documentation: `http://localhost:8000/docs`
   - Alternative docs: `http://localhost:8000/redoc`

### Frontend Setup

1. **Navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```
   
   The frontend will be available at `http://localhost:3000`

## Usage

### Getting Started

1. **Start both servers** (backend on :8000, frontend on :3000)

2. **Create your first vault:**
   - Visit `http://localhost:3000`
   - Click "Create Vault"
   - Choose a unique vault name
   - Create a strong master password (12+ characters with mixed case, numbers, symbols)

3. **Access your vault:**
   - Use the login page to access your vault
   - Your session will remain active for 1 hour

4. **Manage passwords:**
   - View your password list on the dashboard
   - Search through your passwords
   - Copy passwords securely to clipboard
   - Delete passwords when no longer needed

### API Endpoints

#### Vault Management
- `POST /api/v1/vault/create` - Create a new vault
- `POST /api/v1/vault/auth` - Authenticate and get session token
- `POST /api/v1/vault/logout` - Logout and revoke session

#### Password Management
- `GET /api/v1/passwords` - List all passwords (without actual passwords)
- `GET /api/v1/passwords/{service_name}` - Get specific password entry
- `POST /api/v1/passwords` - Store a new password
- `PUT /api/v1/passwords/{entry_id}` - Update existing password
- `DELETE /api/v1/passwords/{entry_id}` - Delete password entry
- `POST /api/v1/passwords/search` - Search passwords
- `POST /api/v1/passwords/generate` - Generate secure password
- `POST /api/v1/passwords/validate` - Validate password strength

#### Utility
- `GET /api/v1/health` - Health check

## CLI Usage

You can also use the command-line interface:

```bash
# Start CLI mode
python main.py --mode cli

# Available CLI commands
python main.py --help
```

## Security Features

### Encryption
- **AES-256-GCM**: Symmetric encryption for password storage
- **Argon2**: Password hashing with configurable parameters
- **Random Salt Generation**: Unique salt for each vault
- **Key Derivation**: Master password derived encryption keys

### Post-Quantum Cryptography
- **liboqs Integration**: Ready for post-quantum algorithms
- **Future-Proof Design**: Modular crypto system for easy algorithm updates

### Zero Trust Architecture
- **No Server-Side Password Storage**: Passwords encrypted before transmission
- **Session-Based Authentication**: JWT tokens with configurable expiration
- **Device Verification**: Placeholder for device trust verification
- **Action Authorization**: Granular permission system

## Development

### Adding New Features

1. **Backend API Endpoints:**
   - Add routes in `pass_vault/api/routes.py`
   - Define models in `pass_vault/api/models.py`
   - Update authentication in `pass_vault/api/auth.py`

2. **Frontend Components:**
   - Add pages in `frontend/src/app/`
   - Create components in `frontend/src/components/`
   - Update API calls in `frontend/src/lib/api.ts`

### Running Tests

```bash
# Test symmetric cryptography
cd pass_vault
python test_symmetric_crypto.py
```

## Configuration

### Environment Variables

**Backend:**
- `JWT_SECRET_KEY`: Secret key for JWT tokens (auto-generated if not set)

**Frontend:**
- `NEXT_PUBLIC_API_URL`: Backend API URL (default: http://localhost:8000/api/v1)

### Security Settings
- Session timeout: 60 minutes (configurable in `pass_vault/api/auth.py`)
- Password requirements: 8+ characters for login, 12+ for registration
- Database: SQLite (easily changeable to PostgreSQL/MySQL)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Security Notice

This password manager is designed with security in mind, but please note:

- Always use strong, unique master passwords
- Keep your master password secure - it cannot be recovered
- Regularly backup your vault database
- Use HTTPS in production environments
- Consider additional authentication factors for high-security use cases

For production deployment, ensure you configure proper SSL/TLS certificates and update default security settings. 