import os
import zipfile
import shutil
import base64
import tempfile
from backend import metrics
from backend.logging_setup import get_logger
from backend.rag import add_document, remove_documents
from backend.memory import memory

logger = get_logger(__name__)
from backend.project_memory import project_memory
from backend.redaction import harvest_secrets
from backend.scanners import run_all_scanners
from backend.session import current


def workspace_dir() -> str:
    """
    The ACTIVE session's workspace — ingested files persist here so
    deterministic scanners can run over them. Created on demand;
    session.py wipes the whole workspace root at startup.
    """
    path = current().workspace
    os.makedirs(path, exist_ok=True)
    return path


def clear_workspace():
    """Wipe only the active session's workspace."""
    path = current().workspace
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)

# =========================================================
# INGESTION LIMITS
# Per-file and zip-expansion caps. The request-level body cap
# lives in main.py; these guard what a request may expand into
# (zip bombs) and what a single file may weigh once decoded.
# =========================================================
MAX_FILE_BYTES = 5 * 1024 * 1024               # single non-zip upload
MAX_ZIP_BYTES = 50 * 1024 * 1024               # uploaded zip archive
MAX_ZIP_MEMBERS = 2000                          # entries per archive
MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # total expanded size

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
    infos = zip_ref.infolist()

    # Zip-bomb guards — checked against the archive's declared
    # sizes BEFORE anything touches the disk.
    if len(infos) > MAX_ZIP_MEMBERS:
        raise ValueError(
            f"archive contains {len(infos)} entries — "
            f"the limit is {MAX_ZIP_MEMBERS}"
        )
    total_uncompressed = sum(i.file_size for i in infos)
    if total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"archive expands to {total_uncompressed // (1024 * 1024)} MB — "
            f"the limit is {MAX_ZIP_UNCOMPRESSED_BYTES // (1024 * 1024)} MB"
        )

    for member in zip_ref.namelist():
        member_path = os.path.join(extract_path, member)
        abs_extract = os.path.abspath(extract_path)
        abs_target = os.path.abspath(member_path)
        if not abs_target.startswith(abs_extract):
            raise ValueError("blocked Zip Slip attack")
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
    extract_path = os.path.join(workspace_dir(), project_name)

    if os.path.exists(extract_path):
        shutil.rmtree(extract_path)
    os.makedirs(extract_path)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        safe_extract(zip_ref, extract_path)

    # GitHub zipballs (and many hand-made zips) wrap everything in a
    # single top-level directory — flatten it so file paths are clean.
    entries = os.listdir(extract_path)
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_path, entries[0])):
        wrapper = os.path.join(extract_path, entries[0])
        for item in os.listdir(wrapper):
            shutil.move(os.path.join(wrapper, item), extract_path)
        os.rmdir(wrapper)

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

    logger.info("ingested project=%s files=%d", project_name, len(indexed_files))
    logger.debug("ingested files: %s", indexed_files)

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
        logger.warning("unsupported file type: %s", original_filename)
        return False

    content = read_file_content(filepath)
    if not content or not content.strip():
        logger.warning("empty or unreadable file: %s", original_filename)
        return False

    # Persist into the scan workspace so scanners can see it.
    # Keep the ORIGINAL filename — scanners like checkov and
    # gitleaks key their rules off names like "Dockerfile"/".tf".
    workspace_path = os.path.join(
        workspace_dir(), os.path.basename(original_filename)
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

    logger.info("ingested file=%s chars=%d", original_filename, len(content))
    return True



def save_uploaded_files(files: list, project_name: str = "default"):
    """
    Expects a list of dicts: {"name": str, "content": base64_str}
    Deduplicates by filename — will not re-ingest a file
    that is already present in memory["files"].

    Returns a list of rejected files as {"name", "reason"} dicts so
    the caller can tell the user WHY an upload did not appear —
    rejections used to be swallowed and looked like silent failures.
    (Deduplicated files are not rejections and are omitted.)
    """
    # Build set of already-ingested filenames
    already_ingested = {f.get("name") for f in memory["files"]}
    ingested_any = False
    rejected = []

    def reject(name, reason):
        logger.warning("rejected upload name=%s reason=%s", name, reason)
        # Bounded label: bucket the free-text reason into a small
        # fixed set so metric cardinality stays flat.
        r = reason.lower()
        if "exceeds" in r:
            cat = "too_large"
        elif "empty" in r:
            cat = "empty"
        elif "decode" in r:
            cat = "decode_error"
        elif "unsupported" in r:
            cat = "unsupported_type"
        elif "no supported files" in r:
            cat = "empty_archive"
        else:
            cat = "other"
        metrics.UPLOADS_REJECTED.labels(reason=cat).inc()
        rejected.append({"name": name, "reason": reason})

    for file in files:

        if not isinstance(file, dict):
            reject(str(type(file)), "unexpected upload format")
            continue

        filename = file.get("name", "unknown")
        b64_content = file.get("content", "")

        # DEDUPLICATION — skip if already in memory (not a rejection)
        if filename in already_ingested:
            logger.debug("already ingested, skipping: %s", filename)
            continue

        if not b64_content:
            reject(filename, "file was empty")
            continue

        try:
            raw_bytes = base64.b64decode(b64_content)
        except Exception:
            reject(filename, "could not decode file content")
            continue

        # Per-file size cap — zips get a higher allowance than
        # plain files since they carry whole projects.
        limit = MAX_ZIP_BYTES if filename.lower().endswith(".zip") else MAX_FILE_BYTES
        if len(raw_bytes) > limit:
            reject(
                filename,
                f"{len(raw_bytes) // (1024 * 1024)} MB exceeds the "
                f"{limit // (1024 * 1024)} MB limit",
            )
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
                logger.info("ingesting zip: %s", filename)
                indexed = ingest_zip(tmp_path)
                if not indexed:
                    reject(filename, "no supported files found in the archive")
                    continue
            else:
                logger.info("ingesting file: %s", filename)
                if not ingest_single_file(
                    filepath=tmp_path,
                    original_filename=filename,
                    project_name=project_name,
                ):
                    reject(filename, "unsupported or unreadable file type")
                    continue
            # Track as ingested
            already_ingested.add(filename)
            ingested_any = True
            metrics.FILES_INGESTED.inc()
        except Exception as e:
            reject(filename, str(e))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # =====================================================
    # RUN DETERMINISTIC SCANNERS
    # One scan per upload batch, cached in memory — every
    # later question reuses these verified findings.
    # =====================================================
    if ingested_any:
        memory["scan"] = run_all_scanners(workspace_dir())

    return rejected


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
        project_path = os.path.join(workspace_dir(), project)
        if os.path.isdir(project_path):
            shutil.rmtree(project_path)
        remove_documents(project_id=project)
    else:
        memory["files"] = [
            f for f in memory["files"] if f.get("name") != name
        ]
        file_path = os.path.join(workspace_dir(), os.path.basename(name))
        if os.path.isfile(file_path):
            os.remove(file_path)
        remove_documents(source=name)

    removed = before - len(memory["files"])

    # Invalidate the RAG query cache and rescan what remains
    memory["rag_cache_key"] = None
    memory["rag_results"] = []
    memory["scan"] = (
        run_all_scanners(workspace_dir()) if memory["files"] else None
    )

    logger.info("removed files=%d for name=%s remaining=%d",
                removed, name, len(memory["files"]))
    return removed