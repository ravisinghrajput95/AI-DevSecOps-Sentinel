import os
import zipfile
import shutil

from backend.rag import add_document
from backend.memory import memory
from backend.project_memory import project_memory

UPLOAD_DIR = "uploads"
EXTRACT_DIR = "extracted"

os.makedirs(
    UPLOAD_DIR,
    exist_ok=True
)

os.makedirs(
    EXTRACT_DIR,
    exist_ok=True
)

SUPPORTED_EXTENSIONS = [

    ".py",
    ".java",
    ".js",
    ".ts",
    ".yaml",
    ".yml",
    ".tf",
    ".tfvars",
    ".json",
    ".xml",
    ".sh",
    ".md",
    ".txt",
    ".properties",
    ".conf",
    ".ini"

]

SPECIAL_FILES = [

    "Dockerfile",
    "pom.xml",
    "Jenkinsfile",
    ".gitlab-ci.yml"

]


def is_supported_file(
    filepath
):

    filename = os.path.basename(
        filepath
    )

    if filename in SPECIAL_FILES:
        return True

    _, ext = os.path.splitext(
        filename
    )

    return ext.lower() in SUPPORTED_EXTENSIONS


def detect_project_type(
    files
):

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


def safe_extract(
    zip_ref,
    extract_path
):

    for member in zip_ref.namelist():

        member_path = os.path.join(
            extract_path,
            member
        )

        abs_extract = os.path.abspath(
            extract_path
        )

        abs_target = os.path.abspath(
            member_path
        )

        if not abs_target.startswith(
            abs_extract
        ):

            raise Exception(
                "Blocked Zip Slip attack"
            )

    zip_ref.extractall(
        extract_path
    )


def ingest_zip(
    zip_path
):

    project_name = os.path.basename(
        zip_path
    ).replace(
        ".zip",
        ""
    )

    extract_path = os.path.join(
        EXTRACT_DIR,
        project_name
    )

    if os.path.exists(
        extract_path
    ):

        shutil.rmtree(
            extract_path
        )

    os.makedirs(
        extract_path
    )

    with zipfile.ZipFile(
        zip_path,
        "r"
    ) as zip_ref:

        safe_extract(
            zip_ref,
            extract_path
        )

    indexed_files = []

    for root, dirs, files in os.walk(
        extract_path
    ):

        dirs[:] = [

            d for d in dirs

            if d not in [

                ".git",
                "node_modules",
                "target",
                "build",
                "__pycache__",
                ".idea",
                ".terraform"

            ]
        ]

        for file in files:

            filepath = os.path.join(
                root,
                file
            )

            if not is_supported_file(
                filepath
            ):

                continue

            try:

                with open(
                    filepath,
                    "r",
                    encoding="utf-8"
                ) as f:

                    content = f.read()

            except:

                try:

                    with open(
                        filepath,
                        "r",
                        encoding="latin-1"
                    ) as f:

                        content = f.read()

                except:
                    continue

            relative_path = os.path.relpath(
                filepath,
                extract_path
            )

            add_document(

                content=content,

                source=relative_path,

                project=project_name,

                topic="repository"

            )

            indexed_files.append(
                relative_path
            )

            memory["files"].append({

                "name": relative_path,
                "content": content[:5000],
                "topic": "repository",
                "project": project_name

            })

    project_type = detect_project_type(
        indexed_files
    )

    project_memory["projects"].append({

        "name": project_name,
        "type": project_type,
        "files": len(indexed_files)

    })

    return indexed_files