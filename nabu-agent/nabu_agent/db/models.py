"""Platform + orchestration ORM (SQLAlchemy 2.0). The recon TRUTH stays in the oscprecon Profile
folder on ``/workspace``; these tables hold product state + read-models + the two-audit-trail's
platform half. Enums align to :class:`nabu_agent.orchestration.states.RunState`.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(20), default="operator")  # rbac.Role
    auth_source: Mapped[str] = mapped_column(String(10), default="local")  # local | oidc
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)  # argon2, local only
    oidc_issuer: Mapped[str | None] = mapped_column(String(320), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(320), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_user_oidc"),)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    engine_profile_dir: Mapped[str] = mapped_column(Text)  # the oscprecon Profile folder
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | archived
    scan_profile: Mapped[str] = mapped_column(String(10), default="default")  # quick|default|exam|full
    spray_enabled: Mapped[bool] = mapped_column(Boolean, default=False)   # per-project gate; default OFF
    exploit_enabled: Mapped[bool] = mapped_column(Boolean, default=False) # per-project gate; default OFF
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    scope_targets: Mapped[list["ScopeTarget"]] = relationship(back_populates="project")


class ProjectMember(Base):
    __tablename__ = "project_members"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # rbac.ProjectRole


class ScopeTarget(Base):
    """The scope-lock allowlist. A discovered pivot must be explicitly PROMOTED here (human-gated)
    before any run may target it."""
    __tablename__ = "scope_targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    target: Mapped[str] = mapped_column(String(120))  # validated via models.validate_host_or_range
    kind: Mapped[str] = mapped_column(String(10), default="host")  # host | range
    is_entry: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual | promoted-pivot
    added_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    project: Mapped[Project] = relationship(back_populates="scope_targets")
    __table_args__ = (UniqueConstraint("project_id", "target", name="uq_scope_target"),)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str] = mapped_column(String(12), default="scan")  # scan|enum|vuln|spray|exploit
    target: Mapped[str] = mapped_column(String(120))  # authorized against scope_targets
    scan_profile: Mapped[str] = mapped_column(String(10), default="default")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(24), default="queued")  # RunState
    limits: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    requested_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    arq_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # NOTE (migration 0001): a partial-unique index on (project_id) WHERE state NOT IN terminal
    # enforces one active run per project.


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    parent_task_id: Mapped[str | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True)
    arq_job_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(12))  # recon|enum|vuln|research|writer|attack
    host: Mapped[str | None] = mapped_column(String(120), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proto: Mapped[str | None] = mapped_column(String(4), nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(12), default="queued")
    shell_outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    llm_tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Checkpoint(Base):
    """The only human gate. A gated action executes ONLY for status=approved + non-null approved_by."""
    __tablename__ = "checkpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("agent_tasks.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(8))  # spray | exploit
    status: Mapped[str] = mapped_column(String(10), default="proposed")
    target: Mapped[str] = mapped_column(String(120))
    action_id: Mapped[str] = mapped_column(String(120))
    rationale: Mapped[str] = mapped_column(Text, default="")
    requires: Mapped[dict] = mapped_column(JSON, default=dict)
    credential_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    exploit_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RunEvent(Base):
    """Durable, seq-ordered replay feed for the WebSocket (distinct from engine audit.jsonl).
    Secrets stripped/hashed — payloads carry credential_ref, never cleartext."""
    __tablename__ = "run_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)  # per-run monotonic
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    type: Mapped[str] = mapped_column(String(32))
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    __table_args__ = (UniqueConstraint("run_id", "seq", name="uq_run_event_seq"),)


class FindingIndex(Base):
    """Read-model of the engine's findings.json (never the source of truth)."""
    __tablename__ = "findings_index"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    host: Mapped[str] = mapped_column(String(120), default="")
    engine_key: Mapped[str] = mapped_column(String(200))
    module: Mapped[str] = mapped_column(String(64), default="")
    kind: Mapped[str] = mapped_column(String(64), default="")
    value: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proto: Mapped[str | None] = mapped_column(String(4), nullable=True)
    category: Mapped[str] = mapped_column(String(16), default="info")
    rank: Mapped[int] = mapped_column(Integer, default=99)
    is_manual: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("project_id", "host", "engine_key", name="uq_finding"),)


class ServiceMirror(Base):
    __tablename__ = "services_mirror"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    host: Mapped[str] = mapped_column(String(120), default="")
    port: Mapped[int] = mapped_column(Integer)
    proto: Mapped[str] = mapped_column(String(4), default="tcp")
    service: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(120), default="")
    __table_args__ = (UniqueConstraint("project_id", "host", "port", "proto", name="uq_service"),)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(24))  # report_md|graph_json|vault_export|...
    path: Mapped[str] = mapped_column(Text)
    filename: Mapped[str] = mapped_column(String(200))
    content_type: Mapped[str] = mapped_column(String(80), default="text/markdown")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Platform who-did-what (distinct from the engine's audit.jsonl)."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(48))  # kebab slug (see nabu_agent.audit)
    object_type: Mapped[str | None] = mapped_column(String(48), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(10), default="success")  # success|denied|error
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64))  # sha256
    scopes: Mapped[dict] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LLMCall(Base):
    """Per-agent LLM call accounting. Raw tool output is NOT persisted verbatim; secrets stripped."""
    __tablename__ = "llm_call"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="")
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    finish_reason: Mapped[str] = mapped_column(String(24), default="")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    retries: Mapped[int] = mapped_column(Integer, default=0)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
