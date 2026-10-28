"""Settings, read from environment variables (or a .env file in the project root)."""
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
ROOT_DIR = Path(__file__).resolve().parents[1]      # project root (the folder with run.py)


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _jwt_secret() -> str:
    """JWT_SECRET from env, else a random secret generated once and kept in .jwt_secret."""
    if os.getenv("JWT_SECRET"):
        return os.environ["JWT_SECRET"]
    f = ROOT_DIR / ".jwt_secret"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
    return f.read_text().strip()


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR.as_posix()}/siem.db")
    admin_token: str = os.getenv("ADMIN_TOKEN", "change-me")          # legacy header token (acts as admin)
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")         # first dashboard user, created on first start
    admin_password: str = os.getenv("ADMIN_PASSWORD", "admin123")
    jwt_secret: str = _jwt_secret()
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))
    retention_interval_hours: float = float(os.getenv("RETENTION_INTERVAL_HOURS", "6"))
    syslog_enabled: bool = _bool("SYSLOG_ENABLED", True)
    syslog_host: str = os.getenv("SYSLOG_HOST", "0.0.0.0")
    syslog_port: int = int(os.getenv("SYSLOG_PORT", "5514"))
    host_online_seconds: int = int(os.getenv("HOST_ONLINE_SECONDS", "90"))
    host_silent_seconds: int = int(os.getenv("HOST_SILENT_SECONDS", "300"))
    # detection
    rules_dir: str = os.getenv("RULES_DIR", str(ROOT_DIR / "rules"))
    config_file: str = os.getenv("CONFIG_FILE", str(ROOT_DIR / "config.yaml"))   # playbooks, threat feeds, geo overrides, hunting queries
    local_utc_offset_minutes: int = int(os.getenv("LOCAL_UTC_OFFSET_MINUTES", "330"))   # 330 = India (IST)
    dedup_window_seconds: int = int(os.getenv("DEDUP_WINDOW_SECONDS", "900"))
    incident_gap_seconds: int = int(os.getenv("INCIDENT_GAP_SECONDS", "1800"))
    risk_half_life_minutes: float = float(os.getenv("RISK_HALF_LIFE_MINUTES", "60"))
    ml_enabled: bool = _bool("ML_ENABLED", True)
    ml_min_history: int = int(os.getenv("ML_MIN_HISTORY", "15"))
    ml_model_path: str = os.getenv("ML_MODEL_PATH", str(ROOT_DIR / "login_iforest.joblib"))
    # enrichment (all optional)
    geoip_db: str = os.getenv("GEOIP_DB", "")                    # path to MaxMind GeoLite2-City.mmdb
    geo_online_lookup: bool = _bool("GEO_ONLINE_LOOKUP", True)   # free ip-api.com fallback
    abuseipdb_key: str = os.getenv("ABUSEIPDB_KEY", "")
    # response
    allowlist_ips: tuple = tuple(_list("ALLOWLIST_IPS"))        # never auto-block these
    # notifications (all optional)
    telegram_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id: str = os.getenv("TELEGRAM_CHAT_ID", "")
    telegram_min_severity: str = os.getenv("NOTIFY_TELEGRAM_MIN", "high")
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "")
    smtp_to: str = os.getenv("SMTP_TO", "")
    email_min_severity: str = os.getenv("NOTIFY_EMAIL_MIN", "critical")
    frontend_dir: str = os.getenv("FRONTEND_DIR", str(ROOT_DIR / "web"))


settings = Settings()
