import os
import zipfile
import shutil
import base64
import tempfile
from backend.rag import add_document
from backend.memory import memory
from backend.project_memory import project_memory

UPLOAD_DIR = "uploads"
EXTRACT_DIR = "extracted"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

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
    extract_path = os.path.join(EXTRACT_DIR, project_name)

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

    if not is_supported_file(filepath):
        print(f"Unsupported file type: {original_filename}")
        return False

    content = read_file_content(filepath)
    if not content or not content.strip():
        print(f"Empty or unreadable file: {original_filename}")
        return False

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
        except Exception as e:
            print(f"Ingest error for {filename}: {e}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)