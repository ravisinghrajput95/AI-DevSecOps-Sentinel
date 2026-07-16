# =========================================================
# SESSION-SCOPED MEMORY
# `memory` keeps its historical dict-style interface
# (memory["files"], memory.get("scan"), ...) but delegates
# to the ACTIVE session's state, so every existing call
# site works unchanged while users stay isolated.
# =========================================================

from backend.session import current


class _SessionMemory:
    def __getitem__(self, key):
        return current().memory[key]

    def __setitem__(self, key, value):
        current().memory[key] = value

    def __contains__(self, key):
        return key in current().memory

    def get(self, key, default=None):
        return current().memory.get(key, default)


memory = _SessionMemory()
