# Architecture

## System Overview

AI DevSecOps Sentinel is a full-stack application that combines:
- **Backend**: Python-based API with AI integration
- **Frontend**: React-based web UI
- **Storage**: Vector DB (FAISS) for semantic search
- **LLM**: OpenAI API for reasoning and analysis

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)              │
│              - File Upload Interface                    │
│              - Chat/Conversation UI                     │
│              - Findings Dashboard                       │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP/REST API
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Backend (FastAPI + Uvicorn)                │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │         Request Router (FastAPI)                │   │
│  │  - /health                                      │   │
│  │  - /chat (POST)                                 │   │
│  │  - File upload handling                         │   │
│  └──────────────────┬──────────────────────────────┘   │
│                     │                                   │
│     ┌───────────────┼───────────────┐                   │
│     ▼               ▼               ▼                   │
│  ┌────────┐  ┌──────────┐  ┌────────────┐              │
│  │ Intent │  │  Prompt  │  │    File    │              │
│  │Engine  │  │  Engine  │  │  Handler   │              │
│  └────────┘  └──────────┘  └────────────┘              │
│     │               │               │                   │
│     └───────────────┼───────────────┘                   │
│                     ▼                                   │
│              ┌──────────────┐                           │
│              │  Memory Mgmt │                           │
│              │  - Files     │                           │
│              │  - Context   │                           │
│              │  - History   │                           │
│              └──────┬───────┘                           │
│                     │                                   │
│     ┌───────────────┼───────────────┐                   │
│     ▼               ▼               ▼                   │
│  ┌────────┐  ┌──────────┐  ┌────────────┐              │
│  │   RAG  │  │ Scanners │  │    LLM     │              │
│  │ (FAISS)│  │ gitleaks │  │ (OpenAI)   │              │
│  │        │  │ checkov  │  │            │              │
│  └────────┘  └──────────┘  └────────────┘              │
└─────────────────────────────────────────────────────────┘
```

## Scanner-Grounded Analysis

Uploaded files are persisted to a `workspace/` directory and scanned
once per upload batch by deterministic tools:

- **gitleaks** — hardcoded secrets (findings are CRITICAL; secret
  values are redacted before storage)
- **checkov** — IaC misconfigurations (Terraform, Kubernetes,
  Dockerfile, Helm, GitHub Actions, docker-compose)

Normalized findings are cached in memory and used two ways:

1. Injected into the file-analysis prompt as a **VERIFIED SCANNER
   FINDINGS** ground-truth section — the LLM correlates, deduplicates,
   and prioritizes them, tagging output `[SCANNER-VERIFIED: <tool>]`
   vs `[AI-DETECTED]`.
2. Returned as structured JSON in the `/chat` response (`findings`,
   `scanners`) and rendered by the frontend's scanner findings panel.

Missing scanners degrade gracefully: the pipeline reports them as
unavailable and the AI notes the coverage gap.

## Component Architecture

### Frontend Layer

**Technology**: React 19 + Vite

```
src/
├── App.jsx              # Main application component
├── components/          # Reusable UI components
├── hooks/              # Custom React hooks
├── utils/              # Utility functions
└── styles/             # CSS/styling
```

**Key Responsibilities**:
- User interface for file upload
- Chat conversation display
- Security findings visualization
- Response streaming display

### Backend Layer

#### 1. **Request Handler** (`main.py`)
- FastAPI application setup
- CORS middleware configuration
- Request routing
- Session management

**Endpoints**:
- `GET /health` - Health check
- `POST /chat` - Main chat endpoint

#### 2. **Intent Detection** (`intent_engine.py`)
- Analyzes user messages
- Detects intent type (security_review, knowledge_ask, etc.)
- Enables appropriate response handling

#### 3. **File Processing** (`file_handler.py`, `zip_handler.py`)
- Handles file uploads
- Extracts ZIP/repository contents
- Processes multiple file formats:
  - Dockerfile
  - Terraform (`.tf`)
  - Kubernetes manifests (`.yaml`)
  - JSON, shell scripts, etc.

#### 4. **Memory Management** (`memory.py`, `project_memory.py`)
- Maintains session state
- Stores uploaded files context
- Tracks conversation history
- Manages vector embeddings

#### 5. **RAG System** (`rag.py`)
- FAISS vector database for semantic search
- Text chunking and embedding
- Document retrieval for context
- Reduces token usage via relevant document selection

#### 6. **Prompt Engine** (`prompt_engine.py`)
- Constructs system prompts
- Builds user prompts with context
- Handles prompt engineering for different intents
- Manages prompt templates

#### 7. **LLM Integration** (`llm.py`)
- OpenAI API integration
- Conversation history management
- Token limit handling
- Response generation

#### 8. **Chunking** (`chunker.py`)
- Splits large files into manageable chunks
- Maintains context overlap
- Preserves code structure

## Data Flow

### File Analysis Flow

```
1. User Upload
   ├── Files sent to /chat endpoint
   ├── Files saved to memory
   └── Extracted if ZIP

2. Processing
   ├── Detect file types
   ├── Chunk large files
   └── Generate embeddings

3. Storage
   ├── Store in FAISS index
   ├── Maintain file references
   └── Index in memory

4. Analysis
   ├── Intent detection
   ├── Relevant document retrieval (RAG)
   └── Prompt construction

5. Response
   ├── OpenAI API call
   ├── Stream response
   └── Return findings
```

### Chat Flow

```
User Message
    ↓
Intent Detection
    ↓
Acknowledgement Check
    ↓
Is Acknowledgement? → Yes → Simple Response
    ↓ No
Build Prompt
    ├── System prompt
    ├── File context (RAG retrieval)
    ├── Conversation history
    └── User message
    ↓
OpenAI API Call
    ↓
Stream Response to Frontend
    ↓
Update Memory (history)
```

## Storage Architecture

### In-Memory Storage
- `memory["files"]` - Uploaded file contents
- `memory["context"]` - Current analysis context
- `memory["history"]` - Conversation history

### Vector Database (FAISS)
- `faiss.index` - Vector embeddings index
- `docs.pkl` - Document chunks and metadata

### File System
- `uploads/` - Raw user uploads
- `extracted/` - Extracted ZIP contents
- `data/` - Sample files for testing

## Technology Stack

### Backend
- **FastAPI** - Web framework
- **Uvicorn** - ASGI server
- **OpenAI** - LLM API
- **FAISS** - Vector similarity search
- **Python 3.9+** - Runtime

### Frontend
- **React 19** - UI framework
- **Vite** - Build tool
- **Node 16+** - Runtime

### Infrastructure
- **CORS** - Cross-origin request handling
- **Pydantic** - Data validation

## Security Considerations

### API Security
- CORS restrictions to localhost
- Input validation via Pydantic
- No secrets in logs
- API key managed via environment variables

### File Handling
- Files stored temporarily
- Extracted contents cleaned up
- Sensitive file analysis (no data sent externally except to OpenAI)

### LLM Integration
- System prompts guide behavior
- Output validation
- History size limits

## Performance Characteristics

### Latency
- File upload: Immediate
- Small query: < 5 seconds
- Large file analysis: 10-30 seconds (depending on file size)

### Scaling
- Session-based memory (per connection)
- FAISS index grows with documents
- OpenAI API rate limits apply

### Resource Usage
- Python backend: ~200MB RAM base + per-file overhead
- Node frontend: ~150MB RAM
- FAISS index: ~500MB per 100k embeddings

## Error Handling

### Backend Errors
- **400** - Bad request (validation error)
- **404** - Not found
- **500** - Server error

### Frontend Error Handling
- Graceful degradation
- Error message display
- Retry logic for API calls

## Future Architecture Improvements

- [ ] Database persistence (PostgreSQL)
- [ ] Multi-user session management
- [ ] WebSocket for real-time streaming
- [ ] Load balancing for horizontal scaling
- [ ] Caching layer (Redis)
- [ ] Audit logging
- [ ] API authentication

---

See [FEATURES.md](FEATURES.md) for detailed feature documentation.
