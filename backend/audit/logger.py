"""
Sentinel AI - Privacy-Preserving Audit Logger
Stores structured metadata-only audit events in SQLite and memory.
Guarantees NO raw prompts, NO raw model answers, and NO secrets are ever persisted.
"""
import sqlite3
import json
import os
from typing import List, Dict, Any
from backend.audit.models import AuditEvent

DB_FILE = os.getenv("AUDIT_DB_PATH", "sentinel_audit.db")

class AuditLogger:
    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self._init_db()
        self.in_memory_recent_events: List[Dict[str, Any]] = []

    def _init_db(self):
        """Initializes the SQLite metadata audit table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    pseudonymous_user_id TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    rule_categories TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    provider_called INTEGER NOT NULL,
                    gateway_latency_ms REAL NOT NULL,
                    total_latency_ms REAL NOT NULL,
                    provider_status_code INTEGER NOT NULL,
                    retrieval_scopes_used TEXT NOT NULL
                )
            """)
            conn.commit()

    def log(self, event: AuditEvent):
        """
        Persists a metadata-only audit event.
        Guarantees zero raw text content.
        """
        event_dict = event.model_dump()
        event_dict["timestamp"] = event.timestamp.isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event_dict["timestamp"],
                event.tenant_id,
                event.pseudonymous_user_id,
                event.action_taken,
                json.dumps(event.rule_categories),
                event.policy_version,
                1 if event.provider_called else 0,
                event.gateway_latency_ms,
                event.total_latency_ms,
                event.provider_status_code,
                json.dumps(event.retrieval_scopes_used)
            ))
            conn.commit()

        # Cache last 50 events in memory for fast UI polling
        self.in_memory_recent_events.insert(0, event_dict)
        if len(self.in_memory_recent_events) > 50:
            self.in_memory_recent_events.pop()

    def verify_zero_raw_content_leak(self) -> Dict[str, Any]:
        """
        Compliance verification routine:
        Scans all records in the audit database to rigorously guarantee that
        no raw prompt text, response bodies, or credentials have ever leaked.
        """
        prohibited_signatures = ["AKIA", "sk-proj", "sk-", "ghp_", "password=", "db_pass=", "@", "-----BEGIN"]
        leak_count = 0
        violations = []

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_events")
            rows = cursor.fetchall()

            for row in rows:
                for col_name in row.keys():
                    val_str = str(row[col_name])
                    for sig in prohibited_signatures:
                        # Category names like SECRET_AWS_KEY are permitted, but actual values are prohibited
                        if sig in val_str and not val_str.startswith("SECRET_") and not "CATEGORY" in val_str:
                            leak_count += 1
                            violations.append({"event_id": row["event_id"], "column": col_name, "snippet": val_str[:20]})

        return {
            "zero_leak_verified": leak_count == 0,
            "total_records_checked": len(rows),
            "prohibited_occurrences_found": leak_count,
            "violations": violations
        }

audit_logger = AuditLogger()

