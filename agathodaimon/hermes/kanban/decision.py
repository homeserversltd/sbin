"""Hermes Kanban decision logic, lifted from Fulcrum.

The body's seats and read-only connection replace lab paths.
"""
from __future__ import annotations
import datetime as dt
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_HERMES_PROFILE = "default"

def hermes_home():
    return Path(os.environ.get("CADUCEUS_HERMES_HOME", "/home/hermes/.hermes"))

def hermes_cli():
    return os.environ.get("CADUCEUS_HERMES_CLI", "/home/hermes/.local/bin/hermes")

def load_cfg():
    return {"paths": {"hermes_config": str(hermes_home() / "config.yaml"), "hermes_cli": hermes_cli()}}

def board_db_path(board):
    if board == "default":
        return hermes_home() / "kanban.db"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", board):
        raise ValueError("invalid board")
    return hermes_home() / "kanban" / "boards" / board / "kanban.db"

def read_hermes_kanban_policy(cfg: dict) -> dict[str, Any]:
    path = Path(cfg.get("paths", {}).get("hermes_config", str(hermes_home() / "config.yaml")))
    policy: dict[str, Any] = {
        "dispatch_stale_timeout_seconds": 0,
        "failure_limit": None,
        "max_in_progress_per_profile": None,
    }
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return policy
    in_kanban = False
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            in_kanban = line.split(":", 1)[0].strip() == "kanban"
            continue
        if not in_kanban or not line.startswith("  ") or ":" not in line:
            continue
        key, raw = line.strip().split(":", 1)
        raw = raw.strip()
        if key in policy:
            if raw in {"", "null", "None"}:
                policy[key] = None
            else:
                try:
                    policy[key] = int(raw)
                except ValueError:
                    policy[key] = raw.strip("'\"")
    return policy


FOUR_D_FIELD_LABELS = {
    "destination": ("destination", "dest"),
    "definition": ("definition", "defined change", "scope definition"),
    "doubt": ("doubt", "proof burden", "uncertainty"),
    "done": ("done", "done gate", "acceptance", "acceptance gate"),
}


FOUR_D_BOUNDARY_LABELS = tuple(
    sorted(
        {
            label
            for labels in FOUR_D_FIELD_LABELS.values()
            for label in labels
        }
        | {
            "repo/surface",
            "repo",
            "surface",
            "scope in",
            "scope out",
            "canonical paths",
            "likely files",
            "receipts to return",
            "cibation membrane",
            "proof commands",
            "constraints",
            "recommended tender",
            "required skills to load",
            "blocker format",
        },
        key=len,
        reverse=True,
    )
)


FOUR_D_THIN_PLACEHOLDERS = (
    "?",
    "??",
    "tbd",
    "todo",
    "unknown",
    "unclear",
    "needs triage",
    "need triage",
    "needs prefill",
    "needs tending",
    "fill in",
    "not sure",
    "n/a",
    "na",
)


def _label_pattern(labels: tuple[str, ...]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(label).replace(r"\ ", r"\s+") for label in labels)
    return re.compile(rf"(?im)^\s*(?:[-*]\s*)?(?:#+\s*)?(?:{alternatives})\s*(?:/\s*[^:\n]+)?\s*:")


def _boundary_pattern() -> re.Pattern[str]:
    alternatives = "|".join(re.escape(label).replace(r"\ ", r"\s+") for label in FOUR_D_BOUNDARY_LABELS)
    return re.compile(rf"(?im)^\s*(?:[-*]\s*)?(?:#+\s*)?(?:{alternatives})\s*(?:/\s*[^:\n]+)?\s*:")


def _field_excerpt(body: str, match: re.Match[str], boundary_re: re.Pattern[str]) -> str:
    next_match = boundary_re.search(body, match.end())
    end = next_match.start() if next_match else len(body)
    return body[match.end():end].strip()


def _field_is_adequate(value: str) -> bool:
    compact = " ".join(value.strip().split())
    if not compact:
        return False
    lowered = compact.lower().strip(" .;:-")
    if lowered in FOUR_D_THIN_PLACEHOLDERS:
        return False
    if any(placeholder in lowered for placeholder in ("needs triage", "needs prefill", "needs tending", "fill in later")):
        return False
    words = re.findall(r"[a-zA-Z0-9][a-zA-Z0-9_/-]*", compact)
    meaningful = [w for w in words if w.lower() not in {"the", "a", "an", "to", "of", "and", "or"}]
    return len(meaningful) >= 2 and len(compact) >= 12


def four_d_envelope_assessment(title: str | None, body: str | None) -> dict[str, Any]:
    """Classify whether a card carries an adequate Four-D execution envelope.

    This is deliberately stronger than checking for the words destination,
    definition, doubt, and done.  The beat is still deterministic; Asmodeus
    remains the final expo/judge.  A thin or placeholder field is treated as a
    governance defect so Asmodeus can keep the same card in triage/prefill
    governance instead of letting a token-complete card drift to ready. The
    governance role retains judgment; all Hermes worker execution is default.
    """
    text = body or ""
    boundary_re = _boundary_pattern()
    missing: list[str] = []
    thin: list[str] = []
    fields: dict[str, str] = {}
    for field, labels in FOUR_D_FIELD_LABELS.items():
        match = _label_pattern(labels).search(text)
        if not match:
            missing.append(field)
            continue
        excerpt = _field_excerpt(text, match, boundary_re)
        fields[field] = " ".join(excerpt.split())[:240]
        if not _field_is_adequate(excerpt):
            thin.append(field)
    adequate = not missing and not thin
    reason = "four-d adequate envelope" if adequate else "four-d inadequate envelope"
    return {
        "adequate": adequate,
        "complete": adequate,
        "missing_fields": missing,
        "thin_fields": thin,
        "fields": fields,
        "reason": reason,
    }


def body_has_four_d(body: str | None) -> bool:
    return bool(four_d_envelope_assessment(None, body).get("adequate"))


def _norm_gate_name(value: str | None) -> str:
    text = (value or "").strip().lower()
    return "".join(ch if ch.isalnum() else "-" for ch in text).strip("-")


def is_ready_one_parent(value: str | None) -> bool:
    name = _norm_gate_name(value)
    return name in {"ready-one", "ready-1", "readyone", "ready-rail", "ready-gate"}


def recommended_tender_for_task(title: str | None, body: str | None, status: str | None = None) -> str:
    # Tender selection is a board assignment, not a Hermes profile router.
    # The estate has one worker profile regardless of task size or lane.
    return DEFAULT_HERMES_PROFILE


def text_mentions_repo_membrane(*parts: str | None) -> bool:
    """Return true when a card appears to cross a repo/publication membrane.

    Fulcrum beat is the rail motor, not the publisher. Repo-backed work may be
    dispatched, but completion is only trusted when the worker result/comment
    carries Cibation review/publication evidence. This lightweight classifier is
    intentionally conservative and deterministic; Asmodeus may sharpen edge
    cases, but the state machine can still identify obvious publication work.
    """
    text = "\n".join(p or "" for p in parts).lower()
    needles = (
        "cibation",
        "sibation",
        "publish",
        "proposal",
        "review_id",
        "paligenesis",
        "palagenesis",
        "/fulcrum/attachments/",
        "work start",
        "work publish",
    )
    return any(n in text for n in needles)


def text_has_publication_receipt(*parts: str | None) -> bool:
    text = "\n".join(p or "" for p in parts).lower()
    needles = (
        "review_id",
        "publish_receipt_id",
        "board_upsert_receipt_id",
        "proposal_ref",
        "proposal_kind",
        "review_visible",
        "rcpt_cibation",
        "cibation_work_publish",
        "cibation-publish",
        "compare:",
    )
    return any(n in text for n in needles)


def fetch_assignment_snapshot(board: str, task_id: str | None = None) -> dict[str, Any]:
    db_path = board_db_path(board)
    if not db_path.exists():
        raise FileNotFoundError(f"kanban db not found for board {board}: {db_path}")
    conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        counts = {row["status"]: row["count"] for row in conn.execute("select status, count(*) as count from tasks group by status")}
        event_through = conn.execute("select max(id) from task_events").fetchone()[0]
        where = "where t.status in ('todo','triage','ready','running','blocked')"
        params: list[Any] = []
        if task_id:
            where += " and t.id = ?"
            params.append(task_id)
        rows = conn.execute(
            f"""
            select t.id, t.status, t.assignee, t.title, t.body, t.created_at,
                   t.started_at, t.max_runtime_seconds, t.last_heartbeat_at,
                   t.current_run_id, t.worker_pid,
                   count(distinct l.parent_id) as parent_count,
                   sum(case when p.status not in ('done','archived') then 1 else 0 end) as unfinished_parent_count,
                   group_concat(distinct p.status) as parent_statuses_csv,
                   group_concat(distinct p.id) as parent_ids_csv,
                   group_concat(distinct p.title) as parent_titles_csv
            from tasks t
            left join task_links l on l.child_id = t.id
            left join tasks p on p.id = l.parent_id
            {where}
            group by t.id, t.status, t.assignee, t.title, t.body, t.created_at,
                     t.started_at, t.max_runtime_seconds, t.last_heartbeat_at,
                     t.current_run_id, t.worker_pid
            order by t.created_at asc
            """,
            params,
        ).fetchall()
        completed_where = "where t.id = ?" if task_id else "where t.status = 'done'"
        completed_rows = conn.execute(
            f"""
            select t.id, t.status, t.assignee, t.title, t.body, t.result, t.completed_at,
                   coalesce(group_concat(c.body, '\n'), '') as comments_text,
                   coalesce(group_concat(e.payload, '\n'), '') as events_text
            from tasks t
            left join task_comments c on c.task_id = t.id
            left join task_events e on e.task_id = t.id
            {completed_where}
            group by t.id, t.status, t.assignee, t.title, t.body, t.result, t.completed_at
            order by coalesce(t.completed_at, t.created_at) desc
            limit 25
            """,
            params if task_id else [],
        ).fetchall()
    finally:
        conn.close()
    tasks: list[dict[str, Any]] = []
    running_by_assignee: dict[str, int] = {}
    for row in rows:
        if row["status"] == "running" and row["assignee"]:
            running_by_assignee[row["assignee"]] = running_by_assignee.get(row["assignee"], 0) + 1
    policy = read_hermes_kanban_policy(load_cfg())
    max_in_progress = policy.get("max_in_progress_per_profile")
    for row in rows:
        parent_count = int(row["parent_count"] or 0)
        unfinished = int(row["unfinished_parent_count"] or 0)
        parent_statuses = [x for x in (row["parent_statuses_csv"] or "").split(",") if x]
        parent_ids = [x for x in (row["parent_ids_csv"] or "").split(",") if x]
        parent_titles = [x for x in (row["parent_titles_csv"] or "").split(",") if x]
        ready_one_parent = any(is_ready_one_parent(x) for x in [*parent_ids, *parent_titles])
        status = row["status"]
        assignee = row["assignee"]
        four_d_assessment = four_d_envelope_assessment(row["title"], row["body"])
        four_d_complete = bool(four_d_assessment.get("adequate"))
        suggested_tender = recommended_tender_for_task(row["title"], row["body"], status)
        if not four_d_complete and status in {"todo", "triage", "ready"}:
            suggested_tender = DEFAULT_HERMES_PROFILE
        cap_reached = bool(assignee and max_in_progress is not None and running_by_assignee.get(assignee, 0) >= int(max_in_progress))
        defect = None
        recommended_action = "skip"
        if status == "triage":
            defect = "triage-needs-governance-prefill"
            recommended_action = "summon-asmodeus"
        elif status in {"todo", "ready"} and assignee and assignee != DEFAULT_HERMES_PROFILE:
            defect = "nondefault-assignee-needs-asmodeus-reassignment"
            recommended_action = "summon-asmodeus"
        elif status == "todo" and parent_count == 0:
            defect = "bulk-unassigned-todo-needs-asmodeus-assignment"
            recommended_action = "summon-asmodeus"
        elif status == "todo" and parent_count > 0 and unfinished > 0:
            defect = "dependency-held-unfinished-parent"
            recommended_action = "hold-record-state"
        elif status == "todo" and parent_count > 0 and unfinished == 0 and assignee and not four_d_complete:
            defect = "dependency-child-four-d-inadequate-needs-governance-prefill"
            recommended_action = "summon-asmodeus"
        elif status == "todo" and parent_count > 0 and unfinished == 0 and ready_one_parent and assignee and four_d_complete and not cap_reached:
            defect = "ready-one-child-releasable"
            recommended_action = "ready-one-release"
        elif status == "todo" and parent_count > 0 and unfinished == 0 and assignee and four_d_complete and not cap_reached:
            defect = "dependency-child-releasable"
            recommended_action = "native-recompute"
        elif status == "todo" and parent_count > 0 and unfinished == 0 and assignee and four_d_complete and cap_reached:
            defect = "dependency-child-release-held-by-profile-cap"
            recommended_action = "hold-record-state"
        elif status == "todo" and parent_count > 0 and unfinished == 0:
            defect = "dependency-child-lacks-assignee-or-four-d-adequate-envelope"
            recommended_action = "summon-asmodeus"
        elif status == "ready" and not four_d_complete:
            defect = "ready-four-d-inadequate-needs-governance-prefill"
            recommended_action = "summon-asmodeus"
        elif status == "ready" and not assignee:
            defect = "unassigned-ready-ownership-defect"
            recommended_action = "summon-asmodeus"
        elif status == "ready" and assignee and cap_reached:
            defect = "ready-assigned-held-by-profile-cap"
            recommended_action = "hold-record-state"
        elif status == "ready" and assignee:
            defect = "ready-assigned-beat-launchable"
            recommended_action = "launch-ready"
        elif status == "running":
            max_runtime = row["max_runtime_seconds"] or policy.get("dispatch_stale_timeout_seconds")
            started_at = row["started_at"] or row["created_at"]
            age = max(0, int(dt.datetime.now(dt.timezone.utc).timestamp()) - int(started_at or 0))
            if max_runtime and age > int(max_runtime):
                defect = "running-over-configured-runtime"
                recommended_action = "reclaim-stale-running"
            else:
                defect = "running-inspect-only"
                recommended_action = "inspect-do-not-steal-pan"
        elif status == "blocked":
            defect = "blocked-human-or-policy-hold"
            recommended_action = "skip"
        tasks.append({
            "id": row["id"],
            "status": status,
            "assignee": assignee,
            "title": row["title"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "max_runtime_seconds": row["max_runtime_seconds"],
            "last_heartbeat_at": row["last_heartbeat_at"],
            "current_run_id": row["current_run_id"],
            "worker_pid": row["worker_pid"],
            "parent_count": parent_count,
            "unfinished_parent_count": unfinished,
            "parent_statuses": parent_statuses,
            "parent_ids": parent_ids,
            "parent_titles": parent_titles,
            "ready_one_parent": ready_one_parent,
            "four_d_complete": four_d_complete,
            "four_d_assessment": four_d_assessment,
            "suggested_tender": suggested_tender,
            "repo_membrane": text_mentions_repo_membrane(row["title"], row["body"]),
            "max_in_progress_per_profile": max_in_progress,
            "running_for_assignee": running_by_assignee.get(assignee or "", 0),
            "defect": defect,
            "recommended_action": recommended_action,
        })
    summonable = [t for t in tasks if t["recommended_action"] == "summon-asmodeus"]
    ready_one_releasable = [t for t in tasks if t["recommended_action"] == "ready-one-release"]
    releasable = [t for t in tasks if t["recommended_action"] == "native-recompute"]
    launchable = [t for t in tasks if t["recommended_action"] == "launch-ready"]
    reclaimable = [t for t in tasks if t["recommended_action"] == "reclaim-stale-running"]
    held = [t for t in tasks if t["recommended_action"] == "hold-record-state"]
    unreceipted_done: list[dict[str, Any]] = []
    for row in completed_rows if Path("/etc/cibation/cibation.json").is_file() else []:
        if row["status"] != "done":
            continue
        repo_membrane = text_mentions_repo_membrane(row["title"], row["body"], row["result"])
        has_receipt = text_has_publication_receipt(row["result"], row["comments_text"], row["events_text"])
        if repo_membrane and not has_receipt:
            unreceipted_done.append({
                "id": row["id"],
                "status": row["status"],
                "assignee": row["assignee"],
                "title": row["title"],
                "completed_at": row["completed_at"],
                "defect": "repo-backed-done-without-cibation-receipt",
                "recommended_action": "receipt-gap-review",
            })
    if summonable:
        decision = "summon-asmodeus"
        reason = "governance defects present"
    elif reclaimable:
        decision = "reclaim-stale-running"
        reason = "running work exceeded configured runtime"
    elif ready_one_releasable:
        decision = "ready-one-release"
        reason = "ready-one parent released assigned Four-D child"
    elif releasable:
        decision = "native-recompute"
        reason = "dependency children are releasable by Fulcrum beat"
    elif launchable:
        decision = "launch-ready"
        reason = "assigned ready work is eligible for Fulcrum Kanban beat-gated worker launch"
    elif unreceipted_done:
        decision = "receipt-gap-review"
        reason = "done repo-backed work lacks Cibation receipt evidence"
    else:
        decision = "skip"
        reason = "no summonable governance defects"
    return {
        "board": board,
        "event_through": event_through,
        "task_filter": task_id,
        "db_path": str(db_path),
        "counts": counts,
        "active_tasks": tasks,
        "summonable_tasks": summonable,
        "ready_one_releasable_tasks": ready_one_releasable,
        "releasable_tasks": releasable,
        "launchable_tasks": launchable,
        "reclaimable_tasks": reclaimable,
        "held_tasks": held,
        "unreceipted_done_tasks": unreceipted_done,
        "running_by_assignee": running_by_assignee,
        "max_in_progress_per_profile": max_in_progress,
        "decision": decision,
        "reason": reason,
    }


def choose_first(tasks: list[dict[str, Any]], *actions: str) -> dict[str, Any] | None:
    wanted = set(actions)
    for task in tasks:
        if task.get("recommended_action") in wanted:
            return task
    return None


def decide_next_management_beat(snapshot: dict[str, Any], revisit_blocked: bool = False) -> dict[str, Any]:
    tasks = snapshot.get("active_tasks", [])
    blocked = [t for t in tasks if t.get("status") == "blocked"]
    running = [t for t in tasks if t.get("status") == "running"]
    # Motion-preserving order: once Asmodeus has assigned a card into ready,
    # fire the hands before asking expo to bless another parentless todo.  This
    # prevents a large unassigned rail from starving already-legitimate work.
    reclaim = choose_first(tasks, "reclaim-stale-running")
    if reclaim:
        return {
            "decision": "reclaim-stale-running",
            "action": "reclaim-stale-running",
            "target_task_id": reclaim.get("id"),
            "target_assignee": reclaim.get("assignee"),
            "reason": "running card exceeded configured runtime and may be reclaimed by the rail motor",
        }
    dispatch = choose_first(tasks, "launch-ready")
    if dispatch:
        return {
            "decision": "launch-ready",
            "action": "launch-assigned-ready",
            "target_task_id": dispatch.get("id"),
            "target_assignee": dispatch.get("assignee"),
            "reason": "ready card has explicit assignee and may be fired by the rail motor",
        }
    ready_one_release = choose_first(tasks, "ready-one-release")
    if ready_one_release:
        return {
            "decision": "ready-one-release",
            "action": "release-ready-one-child",
            "target_task_id": ready_one_release.get("id"),
            "target_assignee": ready_one_release.get("assignee"),
            "reason": "ready-one parent is complete; assigned Four-D child may move to ready and launch",
        }
    release = choose_first(tasks, "native-recompute")
    if release:
        return {
            "decision": "native-recompute",
            "action": "run-native-recompute",
            "target_task_id": release.get("id"),
            "target_assignee": release.get("assignee"),
            "reason": "dependency child is Four-D complete, assigned, and has no unfinished parent; Fulcrum beat may release it",
        }
    summon = choose_first(tasks, "summon-asmodeus")
    if summon:
        return {
            "decision": "assignment-governance",
            "action": "request-asmodeus-assignment-receipt",
            "target_task_id": summon.get("id"),
            "target_assignee": DEFAULT_HERMES_PROFILE,
            "suggested_tender": summon.get("suggested_tender"),
            "reason": f"assignment/triage governance needed: {summon.get('defect')}",
        }
    receipt_gap = choose_first(snapshot.get("unreceipted_done_tasks", []), "receipt-gap-review")
    if receipt_gap:
        return {
            "decision": "receipt-gap-review",
            "action": "hold-receipt-gap",
            "target_task_id": receipt_gap.get("id"),
            "target_assignee": receipt_gap.get("assignee"),
            "reason": "repo-backed done card lacks Cibation publication/review receipt evidence",
        }
    if revisit_blocked and blocked:
        target = next((t for t in blocked if t.get("assignee")), blocked[0])
        if target.get("assignee") and target.get("assignee") != DEFAULT_HERMES_PROFILE:
            return {
                "decision": "assignment-governance",
                "action": "request-asmodeus-assignment-receipt",
                "target_task_id": target.get("id"),
                "target_assignee": DEFAULT_HERMES_PROFILE,
                "suggested_tender": target.get("suggested_tender"),
                "reason": "explicit blocked revisit found a non-default assignee; request Asmodeus reassignment receipt on default instead of unblocking",
            }
        return {
            "decision": "revisit-blocked",
            "action": "unblock-assigned-blocked",
            "target_task_id": target.get("id"),
            "target_assignee": target.get("assignee"),
            "reason": "operator explicitly allowed blocked revisit for manual beat",
        }
    if running:
        target = running[0]
        return {
            "decision": "observe-running",
            "action": "inspect-running-do-not-steal-pan",
            "target_task_id": target.get("id"),
            "target_assignee": target.get("assignee"),
            "reason": "worker already has the pan; observe instead of stealing",
        }
    if blocked:
        target = blocked[0]
        return {
            "decision": "blocked-hold",
            "action": "hold-blocked",
            "target_task_id": target.get("id"),
            "target_assignee": target.get("assignee"),
            "reason": "blocked work requires explicit revisit/unblock authority",
        }
    return {
        "decision": "stable",
        "action": "skip",
        "target_task_id": None,
        "target_assignee": None,
        "reason": "no active management work",
    }


def build_asmodeus_prompt(board: str, task_id: str | None) -> str:
    target = f" and task {task_id}" if task_id else ""
    return (
        f"You are Asmodeus, the seated orchestrator/expo. Run a one-shot assignment pass for board {board}{target}. "
        "Inspect the task/body/events and the todo/triage surface relevant to this task. "
        "Bulk-loaded unassigned todo and parent-child rails are valid intake; do not treat them as malformed. "
        "Asmodeus owns triage/prefill and assignment governance as a role; do not route work to a separate role-named Hermes profile. "
        "All worker execution, including implementation and any delegated tending, uses the default Hermes profile. "
        "You have final judgment: do not equate the presence of Four-D words with an adequate envelope. Judge whether destination, definition, doubt/proof-burden, and done gate are specific enough to execute safely. "
        "If the Four-D envelope is genuinely adequate, assign the lawful tender and route with a ready-assignment receipt. If the card has or needs a ready-one parent gate, use that gate as the release marker before launch. "
        "If the envelope is missing, thin, placeholder-like, or needs more background, preserve the same card count and perform Asmodeus-role triage/prefill governance; any worker execution stays on default. Then read back the returned envelope and bless, block, or assign. "
        "Do not implement repo work yourself. Do not auto-decompose or blow up task counts. "
        f"Do not use dispatch_once as governance. Use the absolute Hermes CLI path {hermes_cli()} and always pass --board explicitly when shelling out. "
        "Read back the final task state before exiting."
    )
