# VAPT Reconnaissance & TLS Assessment Platform

An enterprise-grade security reconnaissance and TLS assessment platform orchestrating real open-source security tools:
- **theHarvester 5.0.0** (Passive OSINT & Hostname Discovery)
- **testssl.sh & Native TLS Engine** (SSL/TLS Protocols, Ciphers, and X.509 Certificate Validation)
- **13-Stage Orchestration State Machine** with live SSE event streaming
- **Automated Security Findings Engine** with CVSS-aligned risk classification
- **Executive Reporting** in PDF, 10-Sheet Excel (.xls), and XML formats
- **Modern Dashboard UI** built with React 19, TypeScript, and Vite

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+ (or Python 3.12+)
- Node.js 18+ and npm
- Git

### 2. Backend Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install fastapi uvicorn sqlalchemy pydantic httpx dnspython reportlab xlwt

# Start backend server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🧪 Testing

Run end-to-end integration tests:
```bash
# Verify API & Mock Pipeline
python tests/verify_e2e.py

# Verify Real Discovery & TLS Assessment Pipeline
python tests/test_real_e2e.py
```

---

## 📦 Deployment Architecture

- **Frontend**: Can be hosted statically on GitHub Pages, Vercel, or Netlify.
- **Backend & Security Tools**: Requires a Python execution environment with network capabilities (VPS, Render, Railway, DigitalOcean, or Docker container) to orchestrate `theHarvester` and live TLS socket probing.
