import os
import zipfile
import shutil
import base64
import tempfile
from backend.rag import add_document, remove_documents
from backend.memory import memory
from backend.project_memory import project_memory
from backend.redaction import harvest_secrets
from backend.scanners import run_all_scanners

# Ingested files are persisted here so deterministic scanners
# (gitleaks, checkov) can run over them. Wiped at startup so its
# lifetime matches the in-memory file store.
WORKSPACE_DIR = "workspace"


def clear_workspace():
    if os.path.exists(WORKSPACE_DIR):
        shutil.rmtree(WORKSPACE_DIR)
    os.makedirs(WORKSPACE_DIR)


clear_workspace()

SUPPORTED_EXTENSIONS = [
    ".py", ".java", ".js", ".ts",
    ".yaml", ".yml", ".tf", ".tfvars",
    ".json", ".xml", ".sh", ".md",
    ".txt", ".properties", ".conf",
    ".ini", ".toml", ".env", ".hcl",
    ".gradle", ".lock", ".mod", ".sum"
]

SPECIAL_FILES = [
    "Dockerfile", "dockerfile",
    "pom.xml", "Jenkinsfile",
    ".gitlab-ci.yml", "Makefile",
    "Taskfile", ".helmignore",
    "docker-compose.yml",
    "docker-compose.yaml"
]


def is_supported_file(filepath):
    filename = os.path.basename(filepath)
    if filename in SPECIAL_FILES:
        return True
    _, ext = os.path.splitext(filename)
    return ext.lower() in SUPPORTED_EXTENSIONS


def detect_project_type(files):
    joined = " ".join(files).lower()
    if "chart.yaml" in joined:
        return "helm"
    if ".tf" in joined:
        return "terraform"
    if "dockerfile" in joined:
        return "docker"
    if "pom.xml" in joined:
        return "java"
    return "general"


def safe_extract(zip_ref, extract_path):
    for member in zip_ref.namelist():
        member_path = os.path.join(extract_path, member)
        abs_extract = os.path.abspath(extract_path)
        abs_target = os.path.abspath(member_path)
        if not abs_target.startswith(abs_extract):
            raise Exception("Blocked Zip Slip attack")
    zip_ref.extractall(extract_path)


def read_file_content(filepath):
    """Read file content with encoding fallback."""
    for encoding in ["utf-8", "latin-1", "cp1252"]:
        try:
            with open(filepath, "r", encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, Exception):
            continue
    return None


def ingest_zip(zip_path):
    project_name = os.path.basename(zip_path).replace(".zip", "")
    extract_path = os.path.join(WORKSPACE_DIR, project_name)

    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    os.makedirs(extract_path)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        safe_extract(zip_ref, extract_path)

    indexed_files = []

    for root, dirs, files in os.walk(extract_path):
        dirs[:] = [
            d for d in dirs
            if d not in [
                ".git", "node_modules", "target",
                "build", "__pycache__", ".idea", ".terraform"
            ]
        ]

        for file in files:
            filepath = os.path.join(root, file)

            if not is_supported_file(filepath):
                continue

            content = read_file_content(filepath)
            if content is None:
                continue

            # Skip empty files
            if not content.strip():
                continue

            relative_path = os.path.relpath(filepath, extract_path)

            # Register credential values for LLM output scrubbing
            harvest_secrets(content)

            # =====================================================
            # STORE FULL REAL CONTENT IN MEMORY
            # No summaries, no truncation of small files
            # Large files capped at 20k chars to avoid context overflow
            # =====================================================

            memory["files"].append({
                "name": relative_path,
                "content": content[:20000],      # full real content
                "topic": "repository",
                "project": project_name
            })

            # =====================================================
            # INDEX FULL REAL CONTENT INTO RAG
            # =====================================================

            add_document(
                content=content,
                source=relative_path,
                project=project_name,
                topic="repository"
            )

            indexed_files.append(relative_path)

    project_type = detect_project_type(indexed_files)

    project_memory["projects"].append({
        "name": project_name,
        "type": project_type,
        "files": len(indexed_files)
    })

    print(f"\n=== INGESTED {len(indexed_files)} FILES FROM {project_name} ===")
    for f in indexed_files:
        print(f"  + {f}")
    print("=" * 50)

    return indexed_files


# =========================================================
# SINGLE FILE INGESTION (non-zip uploads)
# =========================================================

def ingest_single_file(filepath, original_filename, project_name="default"):
    """Ingest a single uploaded file into memory and RAG."""

    # Check the ORIGINAL filename, not the temp path — extension-less
    # special files like "Dockerfile" land in temp storage as "xyz.tmp"
    # and would otherwise always be rejected.
    if not is_supported_file(original_filename):
        print(f"Unsupported file type: {original_filename}")
        return False

    content = read_file_content(filepath)
    if not content or not content.strip():
        print(f"Empty or unreadable file: {original_filename}")
        return False

    # Persist into the scan workspace so scanners can see it.
    # Keep the ORIGINAL filename — scanners like checkov and
    # gitleaks key their rules off names like "Dockerfile"/".tf".
    workspace_path = os.path.join(
        WORKSPACE_DIR, os.path.basename(original_filename)
    )
    shutil.copyfile(filepath, workspace_path)

    # Register credential values for LLM output scrubbing
    harvest_secrets(content)

    memory["files"].append({
        "name": original_filename,
        "content": content[:20000],
        "topic": "file",
        "project": project_name
    })

    add_document(
        content=content,
        source=original_filename,
        project=project_name,
        topic="file"
    )

    print(f"Ingested: {original_filename} ({len(content)} chars)")
    return True



def save_uploaded_files(files: list, project_name: str = "default"):
    """
    Expects a list of dicts: {"name": str, "content": base64_str}
    Deduplicates by filename — will not re-ingest a file
    that is already present in memory["files"].
    """
    # Build set of already-ingested filenames
    already_ingested = {f.get("name") for f in memory["files"]}
    ingested_any = False

    for file in files:

        if not isinstance(file, dict):
            print(f"Skipping unexpected format: {type(file)}")
            continue

        filename = file.get("name", "unknown")
        b64_content = file.get("content", "")

        # DEDUPLICATION — skip if already in memory
        if filename in already_ingested:
            print(f"Already ingested, skipping: {filename}")
            continue

        if not b64_content:
            print(f"Skipping file with no content: {filename}")
            continue

        try:
            raw_bytes = base64.b64decode(b64_content)
        except Exception as e:
            print(f"Base64 decode error for {filename}: {e}")
            continue

        suffix = os.path.splitext(filename)[1] or ".tmp"

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name

        try:
            if filename.lower().endswith(".zip"):
                print(f"Ingesting zip: {filename}")
                ingest_zip(tmp_path)
            else:
                print(f"Ingesting file: {filename}")
                ingest_single_file(
                    filepath=tmp_path,
                    original_filename=filename,
                    project_name=project_name
                )
            # Track as ingested
            already_ingested.add(filename)
            ingested_any = True
        except Exception as e:
            print(f"Ingest error for {filename}: {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # =====================================================
    # RUN DETERMINISTIC SCANNERS
    # One scan per upload batch, cached in memory — every
    # later question reuses these verified findings.
    # =====================================================
    if ingested_any:
        memory["scan"] = run_all_scanners(WORKSPACE_DIR)


# =========================================================
# FILE REMOVAL
# Keeps every store in sync: in-memory file list, workspace
# dir, RAG index — then re-runs the FULL scanner registry
# over what remains so findings from all tools update.
# =========================================================

def remove_uploaded(name: str) -> int:
    """
    Remove a sidebar entry — a single file, or a whole project
    when the entry is a .zip upload. Returns removed file count.
    """
    before = len(memory["files"])

    if name.lower().endswith(".zip"):
        project = os.path.basename(name)[:-4]
        memory["files"] = [
            f for f in memory["files"] if f.get("project") != project
        ]
        project_path = os.path.join(WORKSPACE_DIR, project)
        if os.path.isdir(project_path):
            shutil.rmtree(project_path)
        remove_documents(project_id=project)
    else:
        memory["files"] = [
            f for f in memory["files"] if f.get("name") != name
        ]
        file_path = os.path.join(WORKSPACE_DIR, os.path.basename(name))
        if os.path.isfile(file_path):
            os.remove(file_path)
        remove_documents(source=name)

    removed = before - len(memory["files"])

    # Invalidate the RAG query cache and rescan what remains
    memory["rag_cache_key"] = None
    memory["rag_results"] = []
    memory["scan"] = (
        run_all_scanners(WORKSPACE_DIR) if memory["files"] else None
    )

    print(f"Removed {removed} file(s) for '{name}' — "
          f"{len(memory['files'])} remaining")
    return removed