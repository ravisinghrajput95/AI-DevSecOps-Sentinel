import re

CHUNK_SIZE = 1200
OVERLAP = 200

def chunk_text(text):
    if not text:
        return []

    lines = text.splitlines()
    chunks = []
    current = ""
    for line in lines:
        if len(current) + len(line) < CHUNK_SIZE:
            current += line + "\n"
        else:
            chunks.append(current)
            current = current[-OVERLAP:] + "\n" + line
    if current.strip():
        chunks.append(current)
    return chunks

def chunk_code_by_function(content):
    pattern = r"(def |class |function |resource |module )"
    splits = re.split(pattern, content)
    if len(splits) <= 1:
        return chunk_text(content)
    chunks = []
    current = ""
    for item in splits:
        current += item
        if len(current) > CHUNK_SIZE:
            chunks.append(current)
            current = ""

    if current.strip():
        chunks.append(current)
    return chunks