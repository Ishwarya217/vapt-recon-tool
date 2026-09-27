"""
Centralized Timezone & Datetime Utility for India Standard Time (IST - Asia/Kolkata, UTC+05:30).
All presentation, logging, and report timestamps use this single source of truth.
"""
import datetime
from typing import Optional

try:
    import zoneinfo
    IST = zoneinfo.ZoneInfo("Asia/Kolkata")
except Exception:
    IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")


def now_ist() -> datetime.datetime:
    """Returns current timezone-aware datetime in Asia/Kolkata."""
    return datetime.datetime.now(IST)


def to_ist(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    """
    Converts a datetime (whether naive UTC or timezone-aware) to Asia/Kolkata.
    Assumes naive datetimes stored in SQLite/database are in UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(IST)


def format_ist_datetime(dt: Optional[datetime.datetime]) -> str:
    """
    Formats datetime in standard human-readable IST:
    Example: '14-Sep-2026 10:45:32 AM IST'
    """
    if dt is None:
        return "—"
    ist_dt = to_ist(dt)
    return ist_dt.strftime("%d-%b-%Y %I:%M:%S %p IST")


def format_ist_short(dt: Optional[datetime.datetime]) -> str:
    """
    Formats datetime in short human-readable IST:
    Example: '14-Sep-2026 10:45 AM IST'
    """
    if dt is None:
        return "—"
    ist_dt = to_ist(dt)
    return ist_dt.strftime("%d-%b-%Y %I:%M %p IST")


def format_ist_time(dt: Optional[datetime.datetime]) -> str:
    """
    Formats time portion in IST:
    Example: '10:45:32 AM IST'
    """
    if dt is None:
        return "—"
    ist_dt = to_ist(dt)
    return ist_dt.strftime("%I:%M:%S %p IST")


def format_ist_iso(dt: Optional[datetime.datetime]) -> Optional[str]:
    """
    Formats datetime as unambiguous ISO-8601 with Indian offset:
    Example: '2026-09-14T10:45:32+05:30'
    """
    if dt is None:
        return None
    ist_dt = to_ist(dt)
    return ist_dt.strftime("%Y-%m-%dT%H:%M:%S+05:30")


def format_duration(started_at: Optional[datetime.datetime], completed_at: Optional[datetime.datetime]) -> str:
    """
    Computes and formats scan duration in human-readable form:
    Example: '1m 28s' or '45s'
    """
    if not started_at:
        return "—"
    end = completed_at or datetime.datetime.utcnow()
    diff = end - started_at
    total_seconds = int(diff.total_seconds())
    if total_seconds < 0:
        total_seconds = 0
    mins, secs = divmod(total_seconds, 60)
    if mins > 0:
        return f"{mins}m {secs}s"
    return f"{secs}s"
