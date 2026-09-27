"""Real-time SSE event bus for broadcasting scan progress to connected clients."""
import asyncio
import json
from collections import defaultdict
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, List, Optional


from backend.app.core.time_utils import format_ist_iso, format_ist_time, now_ist


class EventBus:
    def __init__(self):
        self._queues: Dict[str, List[asyncio.Queue]] = defaultdict(list)

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues[scan_id].append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue):
        if scan_id in self._queues:
            self._queues[scan_id] = [x for x in self._queues[scan_id] if x is not q]

    async def publish(self, scan_id: str, event_type: str, message: str, phase: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
        current_ist = now_ist()
        payload = {
            "scan_id": scan_id,
            "event_type": event_type,
            "phase": phase,
            "message": message,
            "data": data or {},
            "timestamp": format_ist_iso(current_ist),
            "timestamp_ist": format_ist_time(current_ist),
        }
        for q in list(self._queues.get(scan_id, [])):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def stream(self, scan_id: str) -> AsyncGenerator[str, None]:
        q = self.subscribe(scan_id)
        seen_keys = set()
        try:
            # Send connection ack
            conn_time = now_ist()
            yield f"data: {json.dumps({'event_type': 'connected', 'scan_id': scan_id, 'message': 'Stream connected', 'timestamp': format_ist_iso(conn_time), 'timestamp_ist': format_ist_time(conn_time)})}\n\n"

            # Replay historical audit logs from DB so the console is immediately populated
            from backend.app.core.database import SessionLocal
            from backend.app.models.models import AuditLog, Scan
            db = SessionLocal()
            is_scan_done = False
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan and scan.status in ("COMPLETED", "FAILED"):
                    is_scan_done = True

                logs = db.query(AuditLog).filter(AuditLog.scan_id == scan_id).order_by(AuditLog.created_at.asc()).all()
                for log in logs:
                    seen_keys.add((log.event_type, log.message))
                    payload = {
                        "scan_id": scan_id,
                        "event_type": log.event_type,
                        "phase": (log.data or {}).get("phase") if isinstance(log.data, dict) else None,
                        "message": log.message,
                        "data": log.data or {},
                        "timestamp": log.created_at.isoformat() if log.created_at else format_ist_iso(conn_time),
                        "timestamp_ist": format_ist_time(log.created_at) if log.created_at else format_ist_time(conn_time),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
            finally:
                db.close()

            if is_scan_done:
                return

            while True:
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=30.0)
                    key = (payload.get("event_type"), payload.get("message"))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    yield f"data: {json.dumps(payload)}\n\n"
                    if payload.get("event_type") in ("completed", "failed"):
                        break
                except asyncio.TimeoutError:
                    # Keepalive
                    yield f": keepalive\n\n"
        finally:
            self.unsubscribe(scan_id, q)


event_bus = EventBus()
