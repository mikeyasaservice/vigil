"""Bounded episodic-memory read for the tenant-local managed connector.

The connector deliberately does not package the backend or its database
session factory. It shares only the pure recall contract and entity-key
normalizer, then performs the same bounded selection with its restricted
``vigil_connector`` role.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from psycopg2.extras import RealDictCursor

from core.memory.entity_keys import normalise_keys
from core.memory.recall_contract import (
    DROPPED_KINDS,
    RECALL_OVERALL_CAP,
    RECALL_PER_KEY_CAP,
    empty_dropped,
    recall_ranking,
)


_PAGE_SQL = {
    "sightings": """
        WITH requested(key) AS (SELECT unnest(%(keys)s::text[])),
        matched AS (
          SELECT count(*)::int AS total FROM episodic_sightings
          WHERE entity_key = ANY(%(keys)s::text[]) AND concluded_at <= %(as_of)s
        ), page AS (
          SELECT p.* FROM requested k CROSS JOIN LATERAL (
            SELECT * FROM episodic_sightings p
            WHERE p.entity_key = k.key AND p.concluded_at <= %(as_of)s
            ORDER BY p.concluded_at DESC, p.id ASC LIMIT %(per_key_cap)s
          ) p
        )
        SELECT matched.total AS matched_total, page.* FROM matched CROSS JOIN page
        ORDER BY page.concluded_at DESC, page.id ASC, page.entity_key ASC
    """,
    "verdicts": """
        WITH requested(key) AS (SELECT unnest(%(keys)s::text[])),
        matched AS (
          SELECT count(*)::int AS total FROM episodic_verdicts
          WHERE subject_entities && %(keys)s::text[] AND concluded_at <= %(as_of)s
        ), page AS (
          SELECT p.* FROM requested k CROSS JOIN LATERAL (
            SELECT * FROM episodic_verdicts p
            WHERE p.subject_entities @> ARRAY[k.key] AND p.concluded_at <= %(as_of)s
            ORDER BY p.concluded_at DESC, p.id ASC LIMIT %(per_key_cap)s
          ) p
        )
        SELECT matched.total AS matched_total, page.* FROM matched CROSS JOIN page
        ORDER BY page.concluded_at DESC, page.id ASC
    """,
    "gaps": """
        WITH requested(key) AS (SELECT unnest(%(keys)s::text[])),
        matched AS (
          SELECT count(*)::int AS total FROM episodic_gaps
          WHERE subject_entities && %(keys)s::text[] AND concluded_at <= %(as_of)s
        ), page AS (
          SELECT p.* FROM requested k CROSS JOIN LATERAL (
            SELECT * FROM episodic_gaps p
            WHERE p.subject_entities @> ARRAY[k.key] AND p.concluded_at <= %(as_of)s
            ORDER BY p.concluded_at DESC, p.id ASC LIMIT %(per_key_cap)s
          ) p
        )
        SELECT matched.total AS matched_total, page.* FROM matched CROSS JOIN page
        ORDER BY page.concluded_at DESC, page.id ASC
    """,
}


def _moment(raw: Any) -> datetime:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return datetime.now(timezone.utc)
    if isinstance(raw, datetime):
        value = raw
    else:
        value = datetime.fromisoformat(str(raw).strip().replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return value


def _shape(kind: str, row: Mapping[str, Any]) -> dict[str, Any]:
    provenance = {
        "investigation_kind": row["investigation_kind"],
        "investigation_id": row["investigation_id"],
        "concluded_at": _iso(row["concluded_at"]),
    }
    if kind == "sightings":
        return {
            **provenance,
            "entity_key": row["entity_key"],
            "source_system": row["source_system"],
            "hit_count": int(row["hit_count"]),
            "attacker_influenceable": bool(row["attacker_influenceable"]),
            "window": {
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
            },
        }
    if kind == "verdicts":
        return {
            **provenance,
            "hypothesis_id": row["hypothesis_id"],
            "statement": row["statement"],
            "outcome": row["outcome"],
            "rationale": row["rationale"],
            "subject_entities": list(row["subject_entities"] or []),
            "attacker_influenceable_only": bool(row["attacker_influenceable_only"]),
            "trust": row["trust"],
            "window": {
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
            },
            "window_source": row["window_source"],
            "sources": [],
        }
    return {
        **provenance,
        "hypothesis_id": row["hypothesis_id"],
        "statement": row["statement"],
        "disposition": row["disposition"],
        "reason": row["reason"],
        "subject_entities": list(row["subject_entities"] or []),
    }


def recall_entity(
    connection: Any,
    args: Mapping[str, Any],
    *,
    max_rows: int,
    timeout_ms: int,
) -> dict[str, Any]:
    keys = args.get("entity_keys")
    if isinstance(keys, str):
        keys = [keys]
    if not keys and args.get("entity_key"):
        keys = [args["entity_key"]]
    normalised = normalise_keys(keys or [])
    if not normalised:
        raise TypeError("recall_entity: a call needs entity_keys or entity_key")
    moment = _moment(args.get("as_of"))
    result: dict[str, Any] = {
        "keys": normalised,
        "as_of": _iso(moment),
        "sightings": [],
        "verdicts": [],
        "gaps": [],
        "dropped": empty_dropped(),
        "ranking": recall_ranking(),
    }
    selected: dict[str, list[dict[str, Any]]] = {}
    params = {
        "keys": normalised,
        "as_of": moment,
        "per_key_cap": RECALL_PER_KEY_CAP,
    }
    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute("SET LOCAL statement_timeout = %s", (timeout_ms,))
        for kind in DROPPED_KINDS:
            cursor.execute(_PAGE_SQL[kind], params)
            rows = cursor.fetchall()
            unique: dict[int, Mapping[str, Any]] = {}
            matched = 0
            for row in rows:
                matched = int(row["matched_total"])
                unique.setdefault(int(row["id"]), row)
            ordered = sorted(
                unique.values(), key=lambda row: (-row["concluded_at"].timestamp(), int(row["id"]))
            )
            selected[kind] = [
                {"id": int(row["id"]), "concluded_at": row["concluded_at"], "value": _shape(kind, row)}
                for row in ordered
            ]
            result["dropped"][kind]["per_key_cap"] = max(0, matched - len(ordered))

        combined = [
            (kind, item) for kind in DROPPED_KINDS for item in selected[kind]
        ]
        combined.sort(
            key=lambda entry: (
                -entry[1]["concluded_at"].timestamp(), entry[0], entry[1]["id"]
            )
        )
        limit = min(RECALL_OVERALL_CAP, max_rows)
        kept = combined[:limit]
        kept_ids = {
            kind: {item["id"] for held_kind, item in kept if held_kind == kind}
            for kind in DROPPED_KINDS
        }
        for kind in DROPPED_KINDS:
            values = [
                item["value"] for held_kind, item in kept if held_kind == kind
            ]
            result[kind] = values
            result["dropped"][kind]["overall_cap"] = len(selected[kind]) - len(values)

        verdict_ids = sorted(kept_ids["verdicts"])
        if verdict_ids:
            cursor.execute(
                """SELECT verdict_id, source_system, stance, source_tier
                   FROM episodic_verdict_sources WHERE verdict_id = ANY(%s::bigint[])
                   ORDER BY verdict_id, source_system""",
                (verdict_ids,),
            )
            verdict_values = {
                item["id"]: item["value"]
                for item in selected["verdicts"] if item["id"] in kept_ids["verdicts"]
            }
            for source in cursor.fetchall():
                verdict_values[int(source["verdict_id"])]["sources"].append(
                    {
                        "source_system": source["source_system"],
                        "stance": source["stance"],
                        "source_tier": source["source_tier"],
                    }
                )

        cursor.execute(
            """INSERT INTO episodic_read_log
                 (caller_kind, caller_id, keys, as_of, row_counts, dropped, ranking)
               VALUES (%s, %s, %s::text[], %s, %s::jsonb, %s::jsonb, %s::jsonb)""",
            (
                str(args.get("caller_kind") or "execution"),
                str(args.get("caller_id") or "unknown"),
                normalised,
                moment,
                json.dumps({kind: len(result[kind]) for kind in DROPPED_KINDS}),
                json.dumps(result["dropped"]),
                json.dumps(result["ranking"]),
            ),
        )
    return result
