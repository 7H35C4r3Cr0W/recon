from oscprecon.modules.redis import (
    parse_redis_clients,
    parse_redis_config,
    parse_redis_info,
)

_INFO = """# Server
redis_version:6.0.16
redis_mode:standalone
os:Linux 5.10.0 x86_64
# Replication
role:master
# Keyspace
db0:keys=3,expires=0
"""

_CONFIG = """maxmemory
0
requirepass

dir
/var/lib/redis
dbfilename
dump.rdb
bind
0.0.0.0
"""

_CLIENTS = """id=3 addr=10.0.0.9:51000 name= age=0 idle=0
id=4 addr=10.0.0.9:51002 name= age=5 idle=1
"""


def test_info_unauth_extracts_version_role_os() -> None:
    kinds = {(f.kind, f.value) for f in parse_redis_info(_INFO)}
    assert ("access", "unauth") in kinds
    assert ("version", "6.0.16") in kinds
    assert ("role", "master") in kinds
    assert any(k == "banner" and "Linux" in v for k, v in kinds)


def test_info_noauth_is_flagged_auth_required() -> None:
    findings = parse_redis_info("NOAUTH Authentication required.")
    assert len(findings) == 1
    assert findings[0].kind == "access" and findings[0].value == "auth-required"


def test_config_flags_empty_requirepass_and_dir() -> None:
    values = {f.value for f in parse_redis_config(_CONFIG)}
    assert "requirepass=<empty>" in values  # no password set
    assert "dir=/var/lib/redis" in values
    assert "dbfilename=dump.rdb" in values


def test_clients_counts_connections() -> None:
    findings = parse_redis_clients(_CLIENTS)
    assert findings and findings[0].kind == "clients" and findings[0].value == "2"
