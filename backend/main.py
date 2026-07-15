# backend/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.prompt_engine import build_prompt
from backend.file_handler import save_uploaded_files, clear_workspace
from backend.llm import ask_openai
from backend.memory import memory
from backend.intent_engine import detect_intent
from backend.rag import clear_rag
from backend.redaction import clear_secrets, scrub_secrets
from backend.scanners import scanner_status

app = FastAPI()

# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# REQUEST MODEL
# =========================================================

class ChatRequest(BaseModel):
    message: str
    history: list = []
    files: list = []

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "files_in_memory": len(memory["files"]),
        "scanners": scanner_status(),
    }

# =========================================================
# CHAT ENDPOINT
# =========================================================

@app.post("/chat")
async def chat(req: ChatRequest):
    user_message = req.message.strip()

    # =====================================================
    # SAVE FILES
    # =====================================================

    if req.files:
        save_uploaded_files(req.files)

    # =====================================================
    # INTENT DETECTION
    # All canned intents (greeting, small talk, clear,
    # acknowledgement, off-topic) are answered here without
    # ever calling the LLM.
    # =====================================================

    intent = detect_intent(user_message)
    print(f"MESSAGE: {user_message}")
    print(f"INTENT:  {intent}")
    print(f"FILES:   {len(memory['files'])} in memory")

    # =====================================================
    # GREETING HANDLER
    # =====================================================

    if intent == "greeting":
        if memory["files"]:
            filenames = ", ".join([
                f["name"] for f in memory["files"][:3]
            ])
            more = len(memory["files"]) - 3
            suffix = f" and {more} more" if more > 0 else ""
            return {
                "response": (
                    f"Hey! I still have your uploaded files in context "
                    f"({filenames}{suffix}).\n\n"
                    f"What would you like to explore next?\n\n"
                    f"- Security audit\n"
                    f"- Misconfiguration review\n"
                    f"- CI/CD analysis\n"
                    f"- Docker / Kubernetes hardening\n"
                    f"- Terraform inspection"
                )
            }
        return {
            "response": (
                "Hey! I'm AI DevSecOps Sentinel — your senior DevOps & DevSecOps engineer.\n\n"
                "I can help you with:\n\n"
                "- **File analysis** — upload a Dockerfile, Terraform, Helm chart, "
                "K8s manifests, CI/CD pipeline, or a full GitHub `.zip`\n"
                "- **Security audits** — secrets, misconfigurations, vulnerable dependencies\n"
                "- **General DevOps knowledge** — CI/CD, Kubernetes, Docker, Terraform, "
                "ArgoCD, Helm, observability, and more\n\n"
                "Upload some files or ask me anything to get started."
            )
        }

    # =====================================================
    # ACKNOWLEDGEMENT HANDLER
    # Catches: "ok", "cool", "great", "thanks", "nice",
    # "awesome", "yep" etc. — never triggers file analysis.
    # =====================================================

    if intent == "acknowledgement":
        if memory["files"]:
            file_count = len(memory["files"])
            return {
                "response": (
                    f"Ready when you are! I have {file_count} file(s) in context.\n\n"
                    f"What would you like to dig into next?\n\n"
                    f"- Security audit\n"
                    f"- Misconfiguration review\n"
                    f"- CI/CD analysis\n"
                    f"- Docker / Kubernetes hardening\n"
                    f"- Terraform inspection"
                )
            }
        return {
            "response": "Ready! What DevOps topic can I help you with?"
        }

    # =====================================================
    # OFF-TOPIC HANDLER
    # Catches non-DevOps questions like "who is Geetanjali",
    # "capital of France", "ipl score" etc.
    # =====================================================

    if intent == "off_topic":
        return {
            "response": (
                "That is outside my area — I am a DevOps and DevSecOps AI assistant. "
                "I can help with Kubernetes, Docker, Terraform, CI/CD pipelines, "
                "security audits, and infrastructure file analysis. "
                "Feel free to ask anything in that space or upload files for a full security review."
            )
        }

    # =====================================================
    # SMALL TALK HANDLER
    # "how are you", "who are you", "what can you do"
    # =====================================================

    if intent == "small_talk":
        msg = user_message.lower().strip()

        if any(x in msg for x in [
            "how are you", "how's it going", "how are things",
            "you good", "are you ok", "how have you been",
            "how is it going", "hows it going"
        ]):
            return {
                "response": (
                    "Running at full capacity. Ready to audit your infrastructure.\n\n"
                    "Upload a file or ask me a DevOps question to get started."
                )
            }

        if any(x in msg for x in [
            "who are you", "what are you", "are you an ai",
            "are you a bot", "are you human", "what is your name",
            "whats your name"
        ]):
            return {
                "response": (
                    "I'm **AI DevSecOps Sentinel** — an AI DevOps and DevSecOps engineer.\n\n"
                    "I specialise in:\n\n"
                    "- Auditing Dockerfiles, Terraform, Kubernetes manifests, "
                    "Helm charts, and CI/CD pipelines\n"
                    "- Detecting hardcoded secrets, misconfigurations, and vulnerable dependencies\n"
                    "- Answering DevOps and DevSecOps questions with real examples and code\n\n"
                    "Upload a file or a GitHub `.zip` to get started."
                )
            }

        if any(x in msg for x in [
            "what can you do", "what do you do",
            "your name", "whats your name"
        ]):
            return {
                "response": (
                    "I'm **AI DevSecOps Sentinel**.\n\n"
                    "**With uploaded files I can:**\n\n"
                    "- Detect hardcoded secrets — AWS keys, tokens, passwords\n"
                    "- Find misconfigurations — open CIDRs, privileged containers, missing TLS\n"
                    "- Identify vulnerable dependencies with exact version details\n"
                    "- Analyse CI/CD pipelines for insecure patterns\n"
                    "- Cross-reference multiple files for conflicts — "
                    "port mismatches, image inconsistencies\n\n"
                    "**Without files I can:**\n\n"
                    "- Answer any DevOps or DevSecOps question\n"
                    "- Explain Kubernetes, Docker, Terraform, Helm, ArgoCD, GitOps\n"
                    "- Give best practice guidance with real code examples\n\n"
                    "Upload a file or ask me anything."
                )
            }

        return {
            "response": (
                "I'm here and ready. What DevOps or DevSecOps topic can I help you with?\n\n"
                "Upload a file for analysis or ask me anything."
            )
        }

    # =====================================================
    # CLEAR HANDLER
    # Clears BOTH the in-memory file store and the RAG
    # vector index — otherwise previously uploaded chunks
    # keep leaking into later analyses via retrieval.
    # =====================================================

    if intent == "clear":
        memory["files"] = []
        memory["last_topic"] = ""
        memory["last_files"] = []
        memory["general_mode"] = False
        memory["rag_cache_key"] = None
        memory["rag_results"] = []
        memory["scan"] = None
        clear_rag()
        clear_workspace()
        clear_secrets()
        return {
            "response": "Context cleared. Upload new files or ask a fresh question."
        }

    # =====================================================
    # BUILD PROMPT + CALL LLM
    # Scanner findings ride along as structured data so the
    # frontend can render them independently of the prose.
    # =====================================================

    prompt = build_prompt(user_message, req.history)
    # Code-level redaction: the model sees raw file contents, so its
    # answer can echo secrets regardless of prompt rules — scrub them.
    answer = scrub_secrets(ask_openai(prompt, req.history))

    scan = memory.get("scan") or {}
    return {
        "response": answer,
        "findings": scan.get("findings", []),
        "scanners": {
            "run": scan.get("tools_run", []),
            "missing": scan.get("tools_missing", []),
        },
    }
