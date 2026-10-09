from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
import asyncio
import getpass
import hashlib
import hmac
import json
from pathlib import Path
import os
import re
import secrets
import sqlite3
import sys
from time import perf_counter
from typing import Annotated, Iterator, Literal
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATABASE_PATH = Path(os.environ.get("SOC_DATABASE_PATH", str(BASE_DIR / "soc.db")))
ADMIN_SESSION_COOKIE = "mrx_soc_session"
SESSION_DURATION = timedelta(hours=8)
PASSWORD_ITERATIONS = 600_000
ADMIN_EMAIL_PATTERN = re.compile(r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@gmail\.com$", re.IGNORECASE)
SIEM_HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
SEED_INCIDENTS = (
    ("INC-2847", "Repeated SSH brute-force attempt", "Perimeter FW", "Critical", "Investigating", "T1110.001", 10),
    ("INC-2845", "Suspicious PowerShell execution", "Endpoint EDR", "High", "New", "T1059.001", 34),
    ("INC-2842", "Credential-harvesting phishing alert", "Email Gateway", "High", "Investigating", "T1566.002", 71),
    ("INC-2839", "Unusual authentication activity", "Identity Provider", "Medium", "Contained", "T1078", 108),
    ("INC-2836", "Anomalous outbound data transfer", "Network Sensor", "Medium", "Investigating", "T1041", 176),
    ("INC-2831", "Suspicious DNS query pattern", "DNS Security", "Low", "Resolved", "T1071.004", 245),
)
NAVIGATION_ORDER = (
    "incidents",
    "threat-intel",
    "mitre",
    "analytics",
    "timeline",
    "settings",
)
REQUIRED_NAVIGATION_ITEMS = frozenset({"overview", "settings"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@contextmanager
def connect_database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_database() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
                status TEXT NOT NULL CHECK (status IN ('Investigating', 'New', 'Contained', 'Resolved')),
                technique TEXT,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                email TEXT NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        existing = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        if existing == 0:
            now = datetime.now(timezone.utc)
            connection.executemany(
                """
                INSERT INTO incidents
                    (id, title, source, severity, status, technique, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        incident_id,
                        title,
                        source,
                        severity,
                        incident_status,
                        technique,
                        None,
                        (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds").replace("+00:00", "Z"),
                        (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    )
                    for (
                        incident_id,
                        title,
                        source,
                        severity,
                        incident_status,
                        technique,
                        minutes_ago,
                    ) in SEED_INCIDENTS
                ],
            )


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)


def current_admin(request: Request) -> str | None:
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not session_token:
        return None
    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    with connect_database() as connection:
        session = connection.execute(
            """
            SELECT admins.email
            FROM auth_sessions
            JOIN admins ON admins.id = 1
            WHERE auth_sessions.token_hash = ? AND auth_sessions.expires_at > ?
            """,
            (token_hash, int(datetime.now(timezone.utc).timestamp())),
        ).fetchone()
    return session["email"] if session else None


def require_admin(request: Request) -> str:
    email = current_admin(request)
    if email is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin login required.")
    return email


def create_admin_account() -> None:
    initialize_database()
    email = input("Admin Gmail address: ").strip().lower()
    if not ADMIN_EMAIL_PATTERN.fullmatch(email):
        raise SystemExit("Enter a valid @gmail.com address.")

    password = getpass.getpass("Admin password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Use a password with at least 12 characters.")
    confirmation = getpass.getpass("Confirm admin password: ")
    if not hmac.compare_digest(password, confirmation):
        raise SystemExit("Passwords do not match.")

    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)
    try:
        with connect_database() as connection:
            connection.execute(
                """
                INSERT INTO admins (id, email, password_salt, password_hash, created_at)
                VALUES (1, ?, ?, ?, ?)
                """,
                (email, salt, password_hash, utc_now()),
            )
    except sqlite3.IntegrityError as error:
        raise SystemExit("An admin account already exists. Do not overwrite it.") from error
    print(f"Admin account created for {email}.")


def reset_admin_password() -> None:
    initialize_database()
    email = input("Current admin Gmail address: ").strip().lower()
    if not ADMIN_EMAIL_PATTERN.fullmatch(email):
        raise SystemExit("Enter a valid @gmail.com address.")

    password = getpass.getpass("New admin password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Use a password with at least 12 characters.")
    confirmation = getpass.getpass("Confirm new admin password: ")
    if not hmac.compare_digest(password, confirmation):
        raise SystemExit("Passwords do not match.")

    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)
    with connect_database() as connection:
        admin = connection.execute("SELECT email FROM admins WHERE id = 1").fetchone()
        if admin is None:
            raise SystemExit("No admin account exists. Run `python main.py create-admin` first.")
        if not hmac.compare_digest(email, admin["email"]):
            raise SystemExit("That Gmail address does not match the configured admin account.")
        connection.execute(
            "UPDATE admins SET password_salt = ?, password_hash = ? WHERE id = 1",
            (salt, password_hash),
        )
        connection.execute("DELETE FROM auth_sessions")
    print(f"Admin password reset for {email}; existing sessions were signed out.")


app = FastAPI(
    title="MR.X | TIP SOC Dashboard API",
    description="Incident management API for the MR.X threat intelligence SOC dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    severity: Literal["Critical", "High", "Medium", "Low"] = "Medium"
    source: str = Field(default="Manual Report", max_length=100)
    status: Literal["Investigating", "New", "Contained", "Resolved"] = "New"
    technique: str | None = Field(default=None, max_length=40)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("title", "source")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("This field cannot be blank.")
        return normalized

    @field_validator("technique", "description")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class IncidentUpdate(BaseModel):
    status: Literal["Investigating", "New", "Contained", "Resolved"] | None = None
    severity: Literal["Critical", "High", "Medium", "Low"] | None = None


class AdminLogin(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class SiemAlert(BaseModel):
    id: str
    provider: Literal["Wazuh", "Splunk"]
    timestamp: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    title: str
    agent: str
    technique: str
    source_ip: str


class NavigationPreferences(BaseModel):
    order: list[str] = Field(min_length=len(NAVIGATION_ORDER), max_length=len(NAVIGATION_ORDER))
    hidden: list[str] = Field(max_length=len(NAVIGATION_ORDER))


def _bool_env(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _verify_setting(prefix: str) -> bool | str:
    ca_bundle = os.environ.get(f"{prefix}_CA_BUNDLE", "").strip()
    if ca_bundle:
        if not Path(ca_bundle).is_file():
            raise ValueError(f"{prefix}_CA_BUNDLE does not point to a readable CA certificate.")
        return ca_bundle
    return _bool_env(f"{prefix}_VERIFY_TLS")


def _endpoint(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _configured_wazuh() -> bool:
    return all(
        os.environ.get(key, "").strip()
        for key in ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USERNAME", "WAZUH_INDEXER_PASSWORD")
    )


def _configured_splunk() -> bool:
    return all(
        os.environ.get(key, "").strip()
        for key in ("SPLUNK_URL", "SPLUNK_TOKEN", "SPLUNK_SEARCH_QUERY")
    )


def _nested(mapping: object, *keys: str) -> object:
    value = mapping
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _first_text(*values: object, default: str = "") -> str:
    for value in values:
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    return default


def _mitre_technique(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("id") or value.get("technique")
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:3] if item)
    return str(value).strip() if value else ""


def _wazuh_severity(value: object) -> Literal["Critical", "High", "Medium", "Low"]:
    try:
        level = int(value)
    except (TypeError, ValueError):
        level = 0
    if level >= 12:
        return "Critical"
    if level >= 8:
        return "High"
    if level >= 4:
        return "Medium"
    return "Low"


def _splunk_severity(value: object, fallback: object = None) -> Literal["Critical", "High", "Medium", "Low"]:
    normalized = _first_text(value, fallback).lower()
    if normalized.isdigit():
        return _wazuh_severity(normalized)
    if normalized in {"critical", "crit", "fatal", "emergency", "alert"}:
        return "Critical"
    if normalized in {"high", "error", "err"}:
        return "High"
    if normalized in {"medium", "warning", "warn", "moderate"}:
        return "Medium"
    return "Low"


def _normalize_wazuh_alert(hit: dict[str, object]) -> dict[str, str]:
    source = hit.get("_source")
    source = source if isinstance(source, dict) else {}
    rule = source.get("rule")
    rule = rule if isinstance(rule, dict) else {}
    data = source.get("data")
    data = data if isinstance(data, dict) else {}
    agent = source.get("agent")
    agent = agent if isinstance(agent, dict) else {}
    mitre = rule.get("mitre")
    timestamp = _first_text(source.get("@timestamp"), source.get("timestamp"), source.get("time"), default=utc_now())
    return {
        "id": _first_text(hit.get("_id"), f"{timestamp}:{rule.get('id', 'wazuh')}"),
        "provider": "Wazuh",
        "timestamp": timestamp,
        "severity": _wazuh_severity(rule.get("level")),
        "title": _first_text(rule.get("description"), source.get("full_log"), default="Wazuh alert")[:240],
        "agent": _first_text(agent.get("name"), agent.get("id"), default="Wazuh Manager"),
        "technique": _mitre_technique(mitre),
        "source_ip": _first_text(
            data.get("srcip"),
            data.get("src_ip"),
            _nested(source, "source", "ip"),
        ),
    }


def _normalize_splunk_alert(envelope: dict[str, object]) -> dict[str, str]:
    result = envelope.get("result")
    result = result if isinstance(result, dict) else envelope
    raw = result.get("_raw")
    event: dict[str, object] = {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                event = parsed
        except json.JSONDecodeError:
            pass
    rule = event.get("rule") or result.get("rule")
    rule = rule if isinstance(rule, dict) else {}
    timestamp = _first_text(
        result.get("_time"),
        event.get("@timestamp"),
        event.get("timestamp"),
        default=utc_now(),
    )
    technique = _first_text(
        result.get("mitre_technique"),
        result.get("technique"),
        event.get("mitre_technique"),
    )
    if not technique:
        technique = _mitre_technique(_nested(event, "rule", "mitre", "id"))
    return {
        "id": _first_text(result.get("_cd"), result.get("event_id"), result.get("id"), f"splunk:{timestamp}"),
        "provider": "Splunk",
        "timestamp": timestamp,
        "severity": _splunk_severity(result.get("severity"), _nested(event, "rule", "level")),
        "title": _first_text(
            result.get("alert_name"),
            result.get("signature"),
            result.get("message"),
            event.get("description"),
            rule.get("description"),
            raw,
            default="Splunk event",
        )[:240],
        "agent": _first_text(result.get("host"), result.get("hostname"), event.get("host"), default="Splunk"),
        "technique": technique,
        "source_ip": _first_text(result.get("src_ip"), result.get("srcip"), event.get("src_ip"), event.get("srcip")),
    }


async def _wazuh_result(limit: int) -> tuple[dict[str, object], list[dict[str, str]]]:
    status_info: dict[str, object] = {"provider": "Wazuh", "status": "not_configured", "count": 0}
    if not _configured_wazuh():
        return status_info, []

    status_info["status"] = "error"
    started = perf_counter()
    try:
        index_pattern = os.environ.get("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-4.x-*").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.*,-]+", index_pattern):
            status_info["error"] = "WAZUH_INDEXER_INDEX_PATTERN contains unsupported characters."
            return status_info, []
        verify = _verify_setting("WAZUH_INDEXER")
        base_url = os.environ["WAZUH_INDEXER_URL"].strip()
        auth = (
            os.environ["WAZUH_INDEXER_USERNAME"].strip(),
            os.environ["WAZUH_INDEXER_PASSWORD"],
        )
        async with httpx.AsyncClient(
            verify=verify,
            timeout=8.0,
            auth=auth,
            transport=SIEM_HTTP_TRANSPORT,
        ) as client:
            response = await client.post(
                _endpoint(base_url, f"{quote(index_pattern, safe='*-._,')}/_search"),
                json={
                    "size": limit,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "query": {"match_all": {}},
                    "_source": [
                        "@timestamp", "timestamp", "time", "rule", "agent", "data", "source", "full_log",
                    ],
                },
            )
            response.raise_for_status()
        payload = response.json()
        hits = _nested(payload, "hits", "hits")
        if not isinstance(hits, list):
            raise ValueError("Wazuh Indexer returned an unexpected alert response.")
        alerts = [_normalize_wazuh_alert(hit) for hit in hits if isinstance(hit, dict)]
        status_info.update(status="connected", count=len(alerts))
        return status_info, alerts
    except httpx.HTTPStatusError as error:
        status_info["error"] = f"Wazuh Indexer returned HTTP {error.response.status_code}."
    except httpx.InvalidURL:
        status_info["error"] = "WAZUH_INDEXER_URL is not a valid HTTP or HTTPS URL."
    except httpx.RequestError:
        status_info["error"] = "Could not connect to Wazuh Indexer; verify its URL, network access, and TLS certificate."
    except (ValueError, json.JSONDecodeError):
        status_info["error"] = "Wazuh Indexer returned an invalid configuration or response."
    finally:
        status_info["checked_at"] = utc_now()
        status_info["latency_ms"] = round((perf_counter() - started) * 1000)
    return status_info, []


def _parse_splunk_export(body: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            if isinstance(payload.get("results"), list):
                return [row for row in payload["results"] if isinstance(row, dict)]
            if isinstance(payload.get("result"), dict):
                return [payload]
    except json.JSONDecodeError:
        pass
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and isinstance(row.get("result"), dict):
            results.append(row)
    return results


async def _splunk_result(limit: int) -> tuple[dict[str, object], list[dict[str, str]]]:
    status_info: dict[str, object] = {"provider": "Splunk", "status": "not_configured", "count": 0}
    if not _configured_splunk():
        return status_info, []

    status_info["status"] = "error"
    started = perf_counter()
    try:
        verify = _verify_setting("SPLUNK")
        base_url = os.environ["SPLUNK_URL"].strip()
        search_query = os.environ["SPLUNK_SEARCH_QUERY"].strip()
        if not re.match(r"^(search|from)\s+", search_query, re.IGNORECASE):
            status_info["error"] = "SPLUNK_SEARCH_QUERY must start with a read-only search or from command."
            return status_info, []
        if re.search(r"\|\s*(outputlookup|collect|sendalert|delete|script)\b", search_query, re.IGNORECASE):
            status_info["error"] = "SPLUNK_SEARCH_QUERY contains a write-capable command."
            return status_info, []
        async with httpx.AsyncClient(
            verify=verify,
            timeout=10.0,
            transport=SIEM_HTTP_TRANSPORT,
        ) as client:
            response = await client.post(
                _endpoint(base_url, "/services/search/jobs/export"),
                headers={"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN'].strip()}"},
                data={
                    "search": search_query,
                    "output_mode": "json",
                    "count": str(limit),
                    "earliest_time": "-24h",
                    "latest_time": "now",
                },
            )
            response.raise_for_status()
        alerts = [_normalize_splunk_alert(row) for row in _parse_splunk_export(response.text)]
        status_info.update(status="connected", count=len(alerts))
        return status_info, alerts
    except httpx.HTTPStatusError as error:
        status_info["error"] = f"Splunk returned HTTP {error.response.status_code}."
    except httpx.InvalidURL:
        status_info["error"] = "SPLUNK_URL is not a valid HTTP or HTTPS URL."
    except httpx.RequestError:
        status_info["error"] = "Could not connect to Splunk; verify its URL, token permissions, network access, and TLS certificate."
    except (ValueError, json.JSONDecodeError):
        status_info["error"] = "Splunk returned an invalid configuration or response."
    finally:
        status_info["checked_at"] = utc_now()
        status_info["latency_ms"] = round((perf_counter() - started) * 1000)
    return status_info, []


def incident_to_dict(row: sqlite3.Row) -> dict[str, object]:
    return dict(row)


@app.get("/", include_in_schema=False)
def dashboard(request: Request) -> Response:
    if current_admin(request) is None:
        return RedirectResponse("/login?next=%2F", status_code=status.HTTP_303_SEE_OTHER)
    return FileResponse(BASE_DIR / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(BASE_DIR / "login.html", headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health() -> dict[str, str]:
    with connect_database() as connection:
        connection.execute("SELECT 1")
    return {"status": "ok", "service": "MR.X TIP SOC Dashboard API"}


@app.post("/api/auth/login")
def login(credentials: AdminLogin, response: Response) -> dict[str, str]:
    email = credentials.email.strip().lower()
    with connect_database() as connection:
        admin = connection.execute(
            "SELECT email, password_salt, password_hash FROM admins WHERE id = 1"
        ).fetchone()

    if admin is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin account is not configured. Run `python main.py create-admin` on the server.",
        )
    password_hash = hash_password(credentials.password, admin["password_salt"])
    if not hmac.compare_digest(email, admin["email"]) or not hmac.compare_digest(
        password_hash, admin["password_hash"]
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    session_token = secrets.token_urlsafe(32)
    expires_at = int((datetime.now(timezone.utc) + SESSION_DURATION).timestamp())
    with connect_database() as connection:
        connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (int(datetime.now(timezone.utc).timestamp()),))
        connection.execute(
            "INSERT INTO auth_sessions (token_hash, expires_at) VALUES (?, ?)",
            (hashlib.sha256(session_token.encode("utf-8")).hexdigest(), expires_at),
        )
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=session_token,
        max_age=int(SESSION_DURATION.total_seconds()),
        httponly=True,
        secure=os.environ.get("SOC_COOKIE_SECURE", "").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"email": admin["email"]}


@app.get("/api/auth/me")
def who_am_i(request: Request) -> dict[str, str | bool]:
    admin_email = current_admin(request)
    if admin_email is None:
        return {"authenticated": False}
    return {"authenticated": True, "email": admin_email}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if session_token:
        token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
        with connect_database() as connection:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_hash,))
    response.delete_cookie(
        key=ADMIN_SESSION_COOKIE,
        httponly=True,
        secure=os.environ.get("SOC_COOKIE_SECURE", "").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"status": "logged out"}


@app.get("/api/incidents")
def list_incidents(
    admin_email: Annotated[str, Depends(require_admin)],
    severity: Literal["Critical", "High", "Medium", "Low"] | None = None,
    incident_status: Annotated[
        Literal["Investigating", "New", "Contained", "Resolved"] | None,
        Query(alias="status"),
    ] = None,
    q: Annotated[str | None, Query(max_length=160)] = None,
) -> list[dict[str, object]]:
    clauses: list[str] = []
    values: list[str] = []
    if severity is not None:
        clauses.append("severity = ?")
        values.append(severity)
    if incident_status is not None:
        clauses.append("status = ?")
        values.append(incident_status)
    if q and q.strip():
        clauses.append("(id LIKE ? OR title LIKE ? OR source LIKE ? OR technique LIKE ?)")
        pattern = f"%{q.strip()}%"
        values.extend((pattern, pattern, pattern, pattern))

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect_database() as connection:
        rows = connection.execute(
            f"SELECT * FROM incidents {where_clause} ORDER BY created_at DESC, id DESC",
            values,
        ).fetchall()
    return [incident_to_dict(row) for row in rows]


@app.post("/api/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(
    incident: IncidentCreate,
    admin_email: Annotated[str, Depends(require_admin)],
) -> dict[str, object]:
    timestamp = utc_now()
    with connect_database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        latest = connection.execute(
            "SELECT MAX(CAST(SUBSTR(id, 5) AS INTEGER)) FROM incidents WHERE id GLOB 'INC-[0-9]*'"
        ).fetchone()[0]
        incident_id = f"INC-{(latest or 2847) + 1}"
        connection.execute(
            """
            INSERT INTO incidents
                (id, title, source, severity, status, technique, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                incident.title,
                incident.source,
                incident.severity,
                incident.status,
                incident.technique,
                incident.description,
                timestamp,
                timestamp,
            ),
        )
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=500, detail="Incident was created but could not be retrieved.")
    return incident_to_dict(row)


@app.get("/api/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    admin_email: Annotated[str, Depends(require_admin)],
) -> dict[str, object]:
    with connect_database() as connection:
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident_to_dict(row)


@app.patch("/api/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    admin_email: Annotated[str, Depends(require_admin)],
) -> dict[str, object]:
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one incident field to update.")
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Incident fields cannot be null.")

    assignments = [f"{field} = ?" for field in changes]
    values = list(changes.values())
    assignments.append("updated_at = ?")
    values.extend((utc_now(), incident_id))
    with connect_database() as connection:
        cursor = connection.execute(
            f"UPDATE incidents SET {', '.join(assignments)} WHERE id = ?",
            values,
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found.")
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=500, detail="Updated incident could not be retrieved.")
    return incident_to_dict(row)


@app.delete("/api/incidents/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: str,
    admin_email: Annotated[str, Depends(require_admin)],
) -> Response:
    with connect_database() as connection:
        cursor = connection.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/threat-indicators")
def list_threat_indicators(
    admin_email: Annotated[str, Depends(require_admin)],
) -> list[dict[str, object]]:
    return [
        {
            "indicator": "198.51.100.42",
            "type": "IPv4",
            "description": "Credential stuffing · Suspicious IP",
            "source": "MR.X Research",
            "confidence": 96,
            "technique": "T1110",
            "technique_name": "Brute Force",
            "sample": True,
        },
        {
            "indicator": "203.0.113.87",
            "type": "IPv4",
            "description": "Known phishing infrastructure",
            "source": "OpenCTI Feed",
            "confidence": 89,
            "technique": "T1566.002",
            "technique_name": "Spearphishing Link",
            "sample": True,
        },
        {
            "indicator": "192.0.2.164",
            "type": "IPv4",
            "description": "C2 beaconing · Malware family: Cobalt Strike",
            "source": "Community Intel",
            "confidence": 82,
            "technique": "T1071.001",
            "technique_name": "Web Protocols",
            "sample": True,
        },
    ]


@app.get("/api/siem/alerts")
async def list_siem_alerts(
    admin_email: Annotated[str, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=200)] = 60,
) -> dict[str, object]:
    provider_results = await asyncio.gather(_wazuh_result(limit), _splunk_result(limit))
    providers = [result[0] for result in provider_results]
    alerts = [alert for _, provider_alerts in provider_results for alert in provider_alerts]
    alerts.sort(key=lambda alert: alert["timestamp"], reverse=True)
    return {
        "generated_at": utc_now(),
        "providers": providers,
        "alerts": alerts[:limit],
        "count": min(len(alerts), limit),
    }


def _navigation_preferences(admin_email: str) -> dict[str, list[str]]:
    with connect_database() as connection:
        row = connection.execute(
            "SELECT setting_value FROM system_settings WHERE setting_key = ?",
            (f"navigation:{admin_email.lower()}",),
        ).fetchone()
    if row is None:
        return {"order": list(NAVIGATION_ORDER), "hidden": []}
    try:
        preferences = json.loads(row["setting_value"])
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=500, detail="Stored navigation preferences are invalid.") from error
    if not isinstance(preferences, dict):
        raise HTTPException(status_code=500, detail="Stored navigation preferences are invalid.")
    order = preferences.get("order")
    hidden = preferences.get("hidden")
    valid_ids = set(NAVIGATION_ORDER)
    if (
        not isinstance(order, list)
        or not all(isinstance(item, str) for item in order)
        or len(order) != len(valid_ids)
        or set(order) != valid_ids
        or not isinstance(hidden, list)
        or not all(isinstance(item, str) for item in hidden)
        or len(hidden) != len(set(hidden))
        or not set(hidden).issubset(valid_ids - REQUIRED_NAVIGATION_ITEMS)
    ):
        raise HTTPException(status_code=500, detail="Stored navigation preferences are invalid.")
    return {"order": order, "hidden": hidden}


@app.get("/api/settings/navigation")
def get_navigation_preferences(
    admin_email: Annotated[str, Depends(require_admin)],
) -> dict[str, list[str]]:
    return _navigation_preferences(admin_email)


@app.put("/api/settings/navigation")
def update_navigation_preferences(
    preferences: NavigationPreferences,
    admin_email: Annotated[str, Depends(require_admin)],
) -> dict[str, list[str]]:
    if len(set(preferences.order)) != len(NAVIGATION_ORDER) or set(preferences.order) != set(NAVIGATION_ORDER):
        raise HTTPException(
            status_code=422,
            detail="Include every configurable navigation section exactly once.",
        )
    if len(set(preferences.hidden)) != len(preferences.hidden):
        raise HTTPException(status_code=422, detail="A navigation section cannot be hidden more than once.")
    if not set(preferences.hidden).issubset(set(NAVIGATION_ORDER) - REQUIRED_NAVIGATION_ITEMS):
        raise HTTPException(status_code=422, detail="Overview and Settings must remain available.")
    serialized = json.dumps({"order": preferences.order, "hidden": preferences.hidden})
    with connect_database() as connection:
        connection.execute(
            """
            INSERT INTO system_settings (setting_key, setting_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(setting_key) DO UPDATE SET
                setting_value = excluded.setting_value,
                updated_at = excluded.updated_at
            """,
            (f"navigation:{admin_email.lower()}", serialized, utc_now()),
        )
    return {"order": preferences.order, "hidden": preferences.hidden}


if __name__ == "__main__":
    commands = {
        "create-admin": create_admin_account,
        "reset-admin-password": reset_admin_password,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        raise SystemExit("Usage: python main.py create-admin | reset-admin-password")
    commands[sys.argv[1]]()
