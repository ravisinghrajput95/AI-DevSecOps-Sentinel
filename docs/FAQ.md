# Frequently Asked Questions

## General Questions

### Q: What is AI DevSecOps Sentinel?

A: AI DevSecOps Sentinel is an AI-powered assistant that analyzes repositories and infrastructure code for security vulnerabilities, misconfigurations, and best practices. It combines security analysis with DevOps knowledge to help teams improve their infrastructure security posture.

### Q: What can it analyze?

A: It analyzes:
- Source code repositories (ZIP files)
- Dockerfiles
- Terraform files (.tf)
- Kubernetes manifests (.yaml/.yml)
- CI/CD workflows
- Configuration files (JSON, etc.)
- And many more formats

### Q: How much does it cost?

A: The application itself is free and open-source. You only pay for OpenAI API usage based on tokens consumed. See [OpenAI pricing](https://openai.com/pricing).

### Q: Can I run it offline?

A: No, it requires OpenAI API access to function. The AI reasoning relies on GPT models via the OpenAI API.

### Q: Is it suitable for enterprise use?

A: The current version is suitable for teams and organizations. For production deployment, consider:
- Adding authentication/authorization
- Implementing audit logging
- Using a persistent database
- Deploying on secure infrastructure
- See [Contributing](CONTRIBUTING.md) for enhancement suggestions

---

## Setup Questions

### Q: Do I need Python and Node.js?

A: Yes, you need both:
- **Python 3.9+** for the backend
- **Node.js 16+** for the frontend

### Q: How do I get an OpenAI API key?

A: 1. Go to [OpenAI Platform](https://platform.openai.com)
   2. Sign up or log in
   3. Navigate to API Keys
   4. Create a new secret key
   5. Add it to `.env`: `OPENAI_API_KEY=sk-...`

### Q: Can I use a different LLM?

A: Currently, only OpenAI is supported. You can modify `backend/llm.py` to add support for other LLMs like Claude, Cohere, or open-source models.

### Q: What ports does it use?

A: - Backend: `8000` (configurable)
   - Frontend: `5173` (configurable)

### Q: Can I change the ports?

A: Yes:
   ```bash
   # Backend
   uvicorn backend.main:app --reload --port 8001
   
   # Frontend
   npm run dev -- --port 5174
   ```

---

## Usage Questions

### Q: How do I upload files?

A: 1. Click "Upload" button in the UI
   2. Select individual files or a ZIP archive
   3. Files are loaded into context
   4. Start asking questions

### Q: Can I upload multiple files?

A: Yes, you can:
- Upload multiple files at once
- Upload a ZIP with entire repository
- Files persist in memory for context

### Q: What file sizes are supported?

A: Recommended:
- Single file: < 5MB
- ZIP archive: < 100MB
- Larger files will take longer to analyze

### Q: How long does analysis take?

A: - Small files: 5-10 seconds
   - Medium files: 10-30 seconds
   - Large repositories: 30-60+ seconds
   - Depends on file complexity and OpenAI API latency

### Q: Can I save analysis results?

A: Currently, results exist in conversation history. To save:
- Copy/paste the response
- Screenshot the findings
- Save the chat history

Future versions may include export functionality.

### Q: Can I clear the file context?

A: Currently, you need to refresh the page. Future versions may include a "clear context" button.

---

## Technical Questions

### Q: How does the security analysis work?

A: 1. **Intent Detection** - Identifies what user is asking
   2. **File Processing** - Parses uploaded files
   3. **Vector Search** - Retrieves relevant file sections using FAISS
   4. **Prompt Building** - Constructs detailed prompt with context
   5. **LLM Analysis** - OpenAI analyzes with system prompts
   6. **Response Generation** - Returns findings with remediation

### Q: What is RAG?

A: RAG (Retrieval-Augmented Generation) is a technique that:
- Converts documents to embeddings (vectors)
- Stores in vector database (FAISS)
- Retrieves relevant sections based on queries
- Includes context in prompts to OpenAI
- This reduces token usage and improves relevance

### Q: How is data stored?

A: Data is stored:
- **In-memory** - Files during session
- **Vector DB** - FAISS index (faiss.index)
- **Pickle** - Document metadata (docs.pkl)
- **Session** - Conversation history in memory

### Q: Is my data secure?

A: - Files are sent to OpenAI for analysis (check OpenAI privacy policy)
- Files not stored on disk (except temp uploads)
- No external logging
- Deploy on trusted infrastructure for production

### Q: Can I use it with my own LLM?

A: Yes, you can modify `backend/llm.py` to use:
- Alternative APIs (Claude, Cohere, etc.)
- Open-source models (Llama, Mistral, etc.)
- Local LLM servers

---

## Performance Questions

### Q: Why is it slow sometimes?

A: Slowness can be due to:
- OpenAI API latency
- Large file processing
- Vector search on large indexes
- System resource constraints

### Q: How can I improve performance?

A: - Use smaller files
   - Ask more specific questions
   - Clear memory between sessions
   - Ensure sufficient system resources
   - Use stable internet connection

### Q: How many files can I analyze?

A: Theoretically unlimited, but:
- FAISS index grows with documents
- Memory increases with file count
- Performance degrades with many files
- Recommended: < 1000 files per session

---

## Feature Questions

### Q: Can it detect secrets in code?

A: Yes! It detects:
- API keys
- Database credentials
- Private keys
- Hardcoded passwords
- And other sensitive data

### Q: Can it provide fixes?

A: It provides remediation guidance and suggestions, but:
- Not automated fixes (yet)
- User must review and implement
- Some fixes require manual review

### Q: Does it support my favorite framework?

A: If you can upload the files, it can analyze them. Specific support includes:
- Docker
- Kubernetes
- Terraform
- AWS CloudFormation
- GitHub Actions
- Helm
- And more

### Q: Can it check compliance?

A: Yes, it maps findings to:
- CWE (Common Weakness Enumeration)
- OWASP
- NIST
- CIS Benchmarks
- MITRE ATT&CK

---

## Integration Questions

### Q: Can I integrate with GitHub?

A: Not yet. Planned features include:
- GitHub Actions integration
- Direct repo import
- PR analysis
- Automated scanning

### Q: Can I use it in CI/CD?

A: Partially - you can call the API from scripts:
```bash
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Analyze for security"}'
```

Full CI/CD integration is planned.

### Q: Is there an API?

A: Yes! See [API.md](API.md) for endpoints:
- `POST /chat` - Send message and files
- `GET /health` - Health check

---

## Troubleshooting Questions

### Q: How do I fix "Port already in use"?

A: ```bash
   # Use different port
   uvicorn backend.main:app --reload --port 8001
   
   # Or kill existing process
   lsof -ti:8000 | xargs kill -9  # Linux/macOS
   ```

### Q: How do I fix CORS errors?

A: Ensure frontend URL is in `backend/main.py`:
   ```python
   allow_origins=[
       "http://localhost:5173",  # Your frontend
   ]
   ```

### Q: How do I fix "Invalid API key"?

A: - Get key from [OpenAI Platform](https://platform.openai.com/account/api-keys)
   - Add to `.env`: `OPENAI_API_KEY=sk-...`
   - Restart backend
   - Verify key has available credits

### Q: How do I see debug logs?

A: - Backend: Check terminal output
   - Frontend: Open browser DevTools (F12)
   - Network tab shows all API calls

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more solutions.

---

## Contributing Questions

### Q: How can I contribute?

A: See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Setting up development environment
- Code guidelines
- Submission process
- Feature requests

### Q: Is this project open-source?

A: Yes! It's open-source and welcomes contributions.

### Q: Can I fork and modify it?

A: Yes, subject to the project's license.

---

## Security Questions

### Q: Is it safe to use?

A: - Run on trusted infrastructure
   - Keep OpenAI API key secure
   - Review uploaded files for sensitive data
   - Don't upload production credentials
   - Check OpenAI data policy

### Q: Will my code be shared?

A: - Code is sent to OpenAI API for analysis
   - Review OpenAI's privacy policy
   - OpenAI uses data for model improvement (opt-out available)
   - Deploy on secure infrastructure

### Q: Can I audit what it sends to OpenAI?

A: Monitor with:
   - Browser Network tab
   - Backend logs
   - OpenAI API activity logs

---

## Future Questions

### Q: What's coming next?

A: Planned features:
- [ ] Multi-user support
- [ ] Database persistence
- [ ] GitHub integration
- [ ] Custom security rules
- [ ] Audit logging
- [ ] API authentication

See [FEATURES.md](FEATURES.md) for more details.

---

## Still Have Questions?

- Check [SETUP.md](SETUP.md) for installation help
- Review [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues
- See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute
- Open an issue on GitHub

---

**Last Updated:** May 2026
