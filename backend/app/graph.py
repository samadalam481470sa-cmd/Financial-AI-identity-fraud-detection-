"""Privacy-limited temporal graph analytics on signed, tenant-scoped events.

This is a deterministic, bounded graph feature extractor; it is NOT a learned
graph neural network, a verified criminal-network label, or an AML determination.
"""
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException

GRAPH_VERSION = "signed-graph-v1"
MAX_EDGES = 5000


def analyze_transfer_graph(c, tenant, subject_ref):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    rows = c.execute(
        """SELECT subject_ref,beneficiary_ref FROM telemetry_events
           WHERE tenant=? AND event_type='transfer_submitted'
             AND occurred_at>=? AND beneficiary_ref IS NOT NULL
           ORDER BY occurred_at DESC LIMIT ?""",
        (tenant, cutoff, MAX_EDGES + 1),
    ).fetchall()
    truncated = len(rows) > MAX_EDGES
    rows = rows[:MAX_EDGES]
    outgoing = defaultdict(set)
    incoming = defaultdict(set)
    undirected = defaultdict(set)
    for item in rows:
        sender, receiver = item["subject_ref"], item["beneficiary_ref"]
        if not sender or not receiver or sender == receiver:
            continue
        outgoing[sender].add(receiver)
        incoming[receiver].add(sender)
        undirected[sender].add(receiver)
        undirected[receiver].add(sender)

    fanout = len(outgoing[subject_ref])
    incoming_sources = len(incoming[subject_ref])
    largest_shared_beneficiary = max(
        (len(incoming[payee]) for payee in outgoing[subject_ref]), default=0
    )
    reciprocal = len(outgoing[subject_ref] & incoming[subject_ref])
    # Count distinct 3-cycles rooted at this account, not transaction volume.
    cycles = set()
    for mid in outgoing[subject_ref]:
        for tail in outgoing[mid]:
            if tail != subject_ref and subject_ref in outgoing[tail]:
                cycles.add((mid, tail))
    short_cycles = len(cycles)

    seen = {subject_ref}
    queue = deque([subject_ref])
    while queue and len(seen) <= 10000:
        node = queue.popleft()
        for neighbor in undirected[node]:
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    connected_size = len(seen)

    reason_codes = []
    score = 0
    if fanout >= 5:
        score += min(22, 3 * fanout)
        reason_codes.append("SIGNED_FANOUT_24H")
    if largest_shared_beneficiary >= 3:
        score += min(18, 4 * largest_shared_beneficiary)
        reason_codes.append("SIGNED_SHARED_BENEFICIARY")
    if reciprocal >= 2:
        score += min(12, 4 * reciprocal)
        reason_codes.append("SIGNED_RECIPROCAL_TRANSFER")
    if short_cycles >= 1:
        score += min(15, 5 * short_cycles)
        reason_codes.append("SIGNED_SHORT_TRANSFER_CYCLE")
    if connected_size >= 15:
        score += 8
        reason_codes.append("SIGNED_LARGE_COMPONENT")

    return min(45, score), reason_codes, {
        "graph_version": GRAPH_VERSION,
        "window_hours": 24,
        "distinct_beneficiaries": fanout,
        "distinct_incoming_sources": incoming_sources,
        "max_shared_beneficiary_sources": largest_shared_beneficiary,
        "reciprocal_neighbor_count": reciprocal,
        "short_3_cycle_count": short_cycles,
        "connected_component_size": connected_size,
        "events_examined": len(rows),
        "truncated": truncated,
        "source": "Ed25519-verified telemetry events only",
        "warning": "These features are investigation leads, not proof of financial wrongdoing.",
    }


def register_graph_routes(app, database, require_analyst):
    @app.get("/v1/graph/accounts/{account_ref}")
    def account_graph(account_ref: str, p=Depends(require_analyst)):
        if not re.fullmatch(r"[0-9a-f]{32}", account_ref):
            raise HTTPException(422, "Expected tenant-scoped 32-hex pseudonymous reference")
        with database() as c:
            risk, reasons, features = analyze_transfer_graph(c, p["tenant"], account_ref)
        return {
            "subject_ref": account_ref, "graph_risk_points": risk,
            "reason_codes": reasons, "features": features,
        }
