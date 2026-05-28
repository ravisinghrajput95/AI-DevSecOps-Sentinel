# Setup Guide

## Prerequisites

- **Python 3.9+** - Backend development
- **Node.js 16+** - Frontend development
- **pip** - Python package manager
- **npm or yarn** - Node package manager
- **OpenAI API Key** - For LLM functionality

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ravisinghrajput95/AI-DevSecOps-Sentinel.git
cd AI-DevSecOps-Sentinel
```

### 2. Backend Setup

#### Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

#### Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### Configure Environment Variables

Create a `.env` file in the root directory:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

### 3. Frontend Setup

```bash
cd frontend
npm install
```

## Running the Application

### Start Backend (FastAPI + Uvicorn)

```bash
# From project root directory
uvicorn backend.main:app --reload --port 8000
```

Backend will be available at: `http://localhost:8000`

Health check: `http://localhost:8000/health`

### Start Frontend (Vite React)

```bash
cd frontend
npm run dev
```

Frontend will be available at: `http://localhost:5173`

## Project Structure

```
DevOps-AI-Assistant/
├── backend/                 # Python FastAPI backend
│   ├── main.py             # FastAPI app entry point
│   ├── llm.py              # OpenAI API integration
│   ├── rag.py              # Vector DB and RAG system
│   ├── intent_engine.py    # Intent detection logic
│   ├── prompt_engine.py    # Prompt building
│   ├── memory.py           # Session memory management
│   ├── file_handler.py     # File processing
│   └── ...
├── frontend/               # React + Vite frontend
│   ├── src/               # React source code
│   ├── package.json       # Node dependencies
│   └── vite.config.js     # Vite configuration
├── docs/                   # Documentation (this folder)
├── data/                   # Sample files for analysis
├── uploads/               # User uploaded files
├── extracted/             # Extracted repository contents
├── requirements.txt       # Python dependencies
└── README.md             # Project overview
```

## Configuration

### OpenAI API Key

1. Get your API key from [OpenAI Dashboard](https://platform.openai.com/account/api-keys)
2. Add it to `.env`:
   ```env
   OPENAI_API_KEY=sk-...
   ```

### CORS Configuration

The backend is configured to accept requests from:
- `http://localhost:3000`
- `http://localhost:5173`
- `http://127.0.0.1:3000`
- `http://127.0.0.1:5173`

Modify `backend/main.py` if using different ports.

## Docker Setup (Optional)

If you prefer to run with Docker:

```bash
# Build the image
docker-compose up

# This will start:
# - Backend on port 8000
# - Frontend on port 5173
```

## Verification

### Backend Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "files_in_memory": 0
}
```

### Frontend Access

Open browser: `http://localhost:5173`

You should see the AI DevSecOps Sentinel UI.

## Troubleshooting

### ModuleNotFoundError

```bash
# Ensure virtual environment is activated
pip install -r requirements.txt
```

### Port Already in Use

```bash
# Change backend port
uvicorn backend.main:app --reload --port 8001

# Change frontend port
npm run dev -- --port 5174
```

### CORS Errors

Check that frontend URL matches CORS allowed origins in `backend/main.py`.

### OpenAI API Errors

- Verify API key is correct
- Check API key has sufficient credits
- Ensure `.env` file is in root directory

See [Troubleshooting](TROUBLESHOOTING.md) for more solutions.

## Next Steps

1. Read the [Architecture Guide](ARCHITECTURE.md) to understand system design
2. Explore the [Features Documentation](FEATURES.md)
3. Check [API Documentation](API.md) for endpoints
4. See [Contributing Guide](CONTRIBUTING.md) to contribute

---

**Need Help?** See [FAQ](FAQ.md) or [Troubleshooting](TROUBLESHOOTING.md)
