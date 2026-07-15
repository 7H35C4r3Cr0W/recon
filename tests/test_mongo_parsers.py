from pathlib import Path

from oscprecon.modules.mongodb import (
    parse_mongo_collections,
    parse_mongo_databases,
    parse_mongo_nmap,
    parse_mongo_version,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "mongodb"


def test_parse_nmap_nse_lists_databases_and_version() -> None:
    findings = parse_mongo_nmap((_FIXTURES / "nmap-info.txt").read_text(encoding="utf-8"))
    kinds = {(f.kind, f.value) for f in findings}
    assert ("access", "unauth") in kinds
    assert ("version", "3.6.8") in kinds
    dbs = {f.value for f in findings if f.kind == "database"}
    assert dbs == {"users", "admin", "config", "local", "sensitive_information"}
    # the storage-engine `name = wiredTiger` (in the mongodb-info block) must NOT be a database
    assert "wiredTiger" not in dbs


def test_parse_nmap_nse_auth_required() -> None:
    text = "| mongodb-databases:\n|_  ERROR: command listDatabases requires authentication\n"
    findings = parse_mongo_nmap(text)
    assert [(f.kind, f.value) for f in findings] == [("access", "auth-required")]


# `print()`-wrapped --eval yields identical text from mongosh and the legacy `mongo` shell.
_DBS_UNAUTH = """DB admin
DB config
DB local
DB sensitive_information
DB users
"""

_COLLECTIONS_UNAUTH = """admin.system.version
config.system.sessions
sensitive_information.flag
users.users
"""

# mongosh throws a MongoServerError to (merged) stderr when access control is on.
_AUTH_MONGOSH = "MongoServerError: command listDatabases requires authentication\n"

# legacy mongo's getDBNames() is an asserting helper — it throws the server errmsg block.
_AUTH_LEGACY = """uncaught exception: Error: listDatabases failed: {
\t"ok" : 0,
\t"errmsg" : "command listDatabases requires authentication",
\t"code" : 13,
\t"codeName" : "Unauthorized"
} :
_getErrorWithCode@src/mongo/shell/utils.js:25:13
"""

# modern mongosh refuses an old (wire v6) server — the signal to retry with the legacy client.
_WIRE = (
    "MongoServerSelectionError: Server at mongod.htb:27017 reports maximum wire version 6, "
    "but this version of the Node.js Driver requires at least 7 (MongoDB 4.0)\n"
)

_CONN = "MongoNetworkError: connect ECONNREFUSED 10.10.10.5:27017\n"
_MISSING = "[missing] mongosh — install with: apt install mongodb-mongosh\n"


def test_version_unauth_extracts_version() -> None:
    findings = parse_mongo_version("3.6.8\n")
    assert [(f.kind, f.value) for f in findings] == [("version", "3.6.8")]


def test_version_strips_ansi_and_takes_last_line() -> None:
    # a pseudo-TTY mongosh wraps the value in SGR escapes; a banner line may leak above it.
    findings = parse_mongo_version("Using MongoDB: 7.0.5\n\x1b[32m7.0.5\x1b[39m\n")
    assert findings and findings[0].value == "7.0.5"


def test_databases_unauth_lists_dbs_and_flags_access() -> None:
    kinds = {(f.kind, f.value) for f in parse_mongo_databases(_DBS_UNAUTH)}
    assert ("access", "unauth") in kinds
    assert ("database", "sensitive_information") in kinds
    assert ("database", "users") in kinds


def test_databases_auth_required_mongosh() -> None:
    findings = parse_mongo_databases(_AUTH_MONGOSH)
    assert len(findings) == 1
    assert (findings[0].kind, findings[0].value) == ("access", "auth-required")


def test_databases_auth_required_legacy() -> None:
    findings = parse_mongo_databases(_AUTH_LEGACY)
    assert findings and findings[0].value == "auth-required"


def test_wire_version_mismatch_becomes_note() -> None:
    findings = parse_mongo_databases(_WIRE)
    assert findings and findings[0].kind == "note"
    assert findings[0].value == "wire-version-mismatch"


def test_connection_error_yields_nothing() -> None:
    assert parse_mongo_databases(_CONN) == []


def test_missing_tool_sentinel_is_skipped() -> None:
    assert parse_mongo_databases(_MISSING) == []
    assert parse_mongo_version(_MISSING) == []
    assert parse_mongo_collections(_MISSING) == []


def test_collections_unauth_maps_namespace() -> None:
    values = {f.value for f in parse_mongo_collections(_COLLECTIONS_UNAUTH)}
    assert "sensitive_information.flag" in values
    assert "admin.system.version" in values
    assert all(f.kind == "collection" for f in parse_mongo_collections(_COLLECTIONS_UNAUTH))


def test_exotic_names_are_not_dropped() -> None:
    # Mongo allows spaces/symbols/unicode in collection names — must not be silently dropped.
    text = "appdb.user sessions\nappdb.naïve\nappdb.cfg#1\n"
    values = {f.value for f in parse_mongo_collections(text)}
    assert {"appdb.user sessions", "appdb.naïve", "appdb.cfg#1"} <= values


def test_error_stack_line_is_not_scraped_as_collection() -> None:
    # a non-auth error trace must not masquerade as db.collection (db part is a restricted token)
    text = "appdb.users\n_getErrorWithCode@src/mongo/shell/utils.js:25:13\n"
    assert {f.value for f in parse_mongo_collections(text)} == {"appdb.users"}


def test_wire_note_emitted_once_by_databases_only() -> None:
    # every command hits the same wire error; only the databases parser emits the note (no dupes)
    assert parse_mongo_version(_WIRE) == []
    assert parse_mongo_collections(_WIRE) == []
    notes = parse_mongo_databases(_WIRE)
    assert len(notes) == 1 and notes[0].value == "wire-version-mismatch"
