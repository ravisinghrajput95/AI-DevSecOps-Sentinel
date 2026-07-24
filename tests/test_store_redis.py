# Redis-backed job registry + session memory, exercised against an
# in-memory fakeredis so the suite needs no live Redis. Confirms the
# externalized backends round-trip, stay session-scoped, and that the
# read-modify-write persistence contract holds.

import fakeredis
import pytest

import backend.store as store
from backend import jobs
from backend.memory import memory
from backend.session import activate


@pytest.fixture
def fake_redis(monkeypatch):
    fake = fakeredis.FakeRedis(decode_responses=True)
    # redis_client() only returns a client when REDIS_URL is set; the
    # cached singleton is what we swap for the fake.
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    monkeypatch.setattr(store, "_redis", fake)
    yield fake


# =========================================================
# JOBS
# =========================================================

def test_job_lifecycle_round_trips_through_redis(fake_redis):
    jid = jobs.create_job("sess-a", "github-ingest")

    job = jobs.get_job(jid)
    assert job["status"] == "running"
    assert job["phase"] == "starting"
    assert job["session_id"] == "sess-a"
    assert isinstance(job["created"], float)

    jobs.set_phase(jid, "scanning")
    jobs.finish_job(jid, {"findings": [1, 2, 3]})

    done = jobs.get_job(jid)
    assert done["status"] == "done"
    assert done["phase"] == "done"
    assert done["result"] == {"findings": [1, 2, 3]}  # dict survived JSON round-trip
    assert done["error"] is None

    assert jobs.public_view(done) == {
        "job_id": jid,
        "status": "done",
        "phase": "done",
        "error": None,
        "result": {"findings": [1, 2, 3]},
    }


def test_job_is_session_scoped(fake_redis):
    jid = jobs.create_job("owner", "github-ingest")
    assert jobs.get_job(jid, "owner") is not None
    assert jobs.get_job(jid, "intruder") is None  # not the caller's job


def test_job_fail_records_error(fake_redis):
    jid = jobs.create_job("sess", "github-ingest")
    jobs.fail_job(jid, "boom")
    job = jobs.get_job(jid)
    assert job["status"] == "error"
    assert job["error"] == "boom"


def test_job_key_carries_ttl(fake_redis):
    jid = jobs.create_job("sess", "github-ingest")
    assert fake_redis.ttl(f"{store.KEY_PREFIX}:job:{jid}") > 0


# =========================================================
# SESSION MEMORY
# =========================================================

def test_memory_default_on_miss(fake_redis):
    activate("mem-fresh")
    # _fresh_memory seeds these; a never-written key still reads its default.
    assert memory["files"] == []
    assert memory["scan"] is None
    assert memory.get("last_topic") == ""


def test_memory_round_trips_and_read_modify_write_persists(fake_redis):
    activate("mem-rw")
    # The append pattern file_handler.py uses under the Redis backend.
    files = memory["files"]
    files.append({"name": "a.tf", "content": "x"})
    memory["files"] = files

    reread = memory["files"]
    assert reread == [{"name": "a.tf", "content": "x"}]


def test_memory_is_session_scoped(fake_redis):
    activate("sess-1")
    memory["files"] = [{"name": "one"}]

    activate("sess-2")
    assert memory["files"] == []  # sess-2 sees nothing from sess-1

    activate("sess-1")
    assert memory["files"] == [{"name": "one"}]


def test_memory_contains(fake_redis):
    activate("mem-contains")
    assert "files" in memory          # fresh key always present
    assert "nonsense" not in memory
    memory["custom"] = 1
    assert "custom" in memory
