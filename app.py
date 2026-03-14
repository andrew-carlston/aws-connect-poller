"""AWS Connect Agent State Poller.

Polls AWS Connect API every 60 seconds for agent state snapshots.
Writes each snapshot to Supabase for WFM interval analysis.
Checks status thresholds and sends Slack notifications for breaches.

Deployed on Render as a web service with a /poll endpoint
triggered by an external cron (cron-job.org) or Render cron job.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone, timedelta

import boto3
import requests
from flask import Flask, jsonify, request

log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Config from environment ──────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")  # service role key
POLL_SECRET = os.environ.get("POLL_SECRET", "")
COMPANY_ID = os.environ.get("COMPANY_ID", "")  # tenant UUID
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_CONNECT_INSTANCE_ID = os.environ.get("AWS_CONNECT_INSTANCE_ID", "")


# ── User mapping cache ────────────────────────────────────────
_user_cache = {}
_rp_cache = {}
_user_cache_ts = None
USER_CACHE_TTL = timedelta(minutes=10)


def refresh_user_cache(client):
    """Load all users and routing profiles from AWS Connect."""
    global _user_cache, _rp_cache, _user_cache_ts

    # Users
    users = {}
    next_token = None
    while True:
        kwargs = {"InstanceId": AWS_CONNECT_INSTANCE_ID}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = client.list_users(**kwargs)
        for u in resp.get("UserSummaryList", []):
            users[u["Id"]] = {"email": u.get("Username", "")}
        next_token = resp.get("NextToken")
        if not next_token:
            break

    # Routing profiles
    rps = {}
    next_token = None
    try:
        while True:
            kwargs = {"InstanceId": AWS_CONNECT_INSTANCE_ID}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.list_routing_profiles(**kwargs)
            for rp in resp.get("RoutingProfileSummaryList", []):
                rps[rp["Id"]] = rp.get("Name", "")
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except Exception:
        pass

    _user_cache = users
    _rp_cache = rps
    _user_cache_ts = datetime.now(timezone.utc)
    return users


def get_user_mapping(client):
    """Return cached user mapping, refreshing if stale."""
    if (
        _user_cache_ts is None
        or datetime.now(timezone.utc) - _user_cache_ts > USER_CACHE_TTL
    ):
        refresh_user_cache(client)
    return _user_cache


# ── AWS Connect helpers ──────────────────────────────────────

def get_filter_ids(client):
    """Get filter IDs for get_current_user_data. Tries queues, then routing profiles."""
    # Try listing queues first
    try:
        queue_ids = []
        next_token = None
        while True:
            kwargs = {"InstanceId": AWS_CONNECT_INSTANCE_ID, "QueueTypes": ["STANDARD"]}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.list_queues(**kwargs)
            for q in resp.get("QueueSummaryList", []):
                queue_ids.append(q["Id"])
            next_token = resp.get("NextToken")
            if not next_token:
                break
        if queue_ids:
            return {"Queues": queue_ids}
    except Exception:
        pass

    # Try routing profiles
    try:
        rp_ids = []
        next_token = None
        while True:
            kwargs = {"InstanceId": AWS_CONNECT_INSTANCE_ID}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = client.list_routing_profiles(**kwargs)
            for rp in resp.get("RoutingProfileSummaryList", []):
                rp_ids.append(rp["Id"])
            next_token = resp.get("NextToken")
            if not next_token:
                break
        if rp_ids:
            return {"RoutingProfiles": rp_ids}
    except Exception:
        pass

    return None


def poll_aws_connect(client=None):
    """Call AWS Connect get_current_user_data and return agent state list."""
    if client is None:
        client = boto3.client("connect", region_name=AWS_REGION)

    filters = get_filter_ids(client)
    if not filters:
        raise Exception("No permission to list queues or routing profiles — cannot filter get_current_user_data")

    agents = []
    next_token = None

    while True:
        kwargs = {
            "InstanceId": AWS_CONNECT_INSTANCE_ID,
            "Filters": filters,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        resp = client.get_current_user_data(**kwargs)

        for user_data in resp.get("UserDataList", []):
            user = user_data.get("User", {})
            status = user_data.get("Status", {})
            contacts = user_data.get("Contacts", [])
            routing = user_data.get("RoutingProfile", {})

            status_start = status.get("StatusStartTimestamp")
            status_start_iso = status_start.isoformat() if status_start else None

            status_duration = None
            if status_start:
                status_duration = int(
                    (datetime.now(timezone.utc) - status_start.replace(tzinfo=timezone.utc)).total_seconds()
                )

            # Build contact list with timestamps
            contact_list = []
            for c in contacts:
                connected_ts = c.get("ConnectedToAgentTimestamp")
                state_ts = c.get("StateStartTimestamp")
                contact_list.append({
                    "id": c.get("ContactId", ""),
                    "channel": c.get("Channel", ""),
                    "state": c.get("AgentContactState", ""),
                    "queue": c.get("Queue", {}).get("Name", ""),
                    "connected_at": connected_ts.isoformat() if connected_ts else None,
                    "state_start": state_ts.isoformat() if state_ts else None,
                })

            # Determine effective status from contact states
            has_connected = any(
                c["state"] in ("CONNECTED", "CONNECTED_ONHOLD")
                for c in contact_list
            )
            has_acw = any(c["state"] == "ENDED" for c in contact_list)

            raw_status = status.get("StatusName", "")
            if has_connected:
                effective_status = "On Contact"
            elif has_acw:
                effective_status = "After Contact Work"
            else:
                effective_status = raw_status

            # Use StateStartTimestamp for contact/ACW duration
            effective_start = status_start_iso
            effective_duration = status_duration
            if has_connected or has_acw:
                for c in contact_list:
                    if has_connected and c["state"] not in ("CONNECTED", "CONNECTED_ONHOLD"):
                        continue
                    if has_acw and c["state"] != "ENDED":
                        continue
                    # state_start = when this contact state began (most accurate)
                    # connected_at = when call first connected (fallback for On Contact)
                    ts = c.get("state_start") or (c.get("connected_at") if has_connected else None)
                    if ts:
                        effective_start = ts
                        ct = datetime.fromisoformat(ts)
                        effective_duration = int(
                            (datetime.now(timezone.utc) - ct.replace(tzinfo=timezone.utc)).total_seconds()
                        )
                    break

            agents.append({
                "user_id": user.get("Id", ""),
                "status_name": effective_status,
                "status_start_utc": effective_start,
                "status_duration": effective_duration,
                "routing_profile_id": routing.get("Id", ""),
                "contacts": json.dumps(contact_list) if contact_list else None,
            })

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return agents


def write_to_supabase(agents, snapshot_ts, user_mapping, rp_mapping):
    """Write agent snapshot rows to Supabase."""
    rows = []
    for a in agents:
        info = user_mapping.get(a["user_id"], {})

        rows.append({
            "company_id": COMPANY_ID,
            "snapshot_ts": snapshot_ts,
            "user_id": a["user_id"],
            "agent_email": info.get("email", ""),
            "status_name": a["status_name"],
            "status_start_utc": a["status_start_utc"],
            "status_duration": a["status_duration"],
            "routing_profile": rp_mapping.get(a["routing_profile_id"], ""),
            "contacts": a["contacts"],  # already JSON string or None
        })

    if not rows:
        return 0, None

    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/aws_agent_snapshots",
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        },
        json=rows,
        timeout=30,
    )

    if resp.status_code not in (200, 201):
        return 0, f"Supabase error {resp.status_code}: {resp.text[:500]}"

    return len(rows), None


# ── Threshold notifications + auto-infractions ──────────────

def _sb_get(path, params=None):
    """GET from Supabase REST API."""
    resp = requests.get(
        f"{SUPABASE_URL}/rest/v1/{path}",
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        },
        params=params or {},
        timeout=15,
    )
    return resp.json() if resp.status_code == 200 else []


def _sb_post(table, rows):
    """POST rows to Supabase REST API."""
    resp = requests.post(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        },
        json=rows,
        timeout=15,
    )
    return resp.json() if resp.status_code in (200, 201) else None


def _sb_patch(table, match, updates):
    """PATCH rows matching filters."""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    params = {f"{k}": f"eq.{v}" for k, v in match.items()}
    requests.patch(
        url,
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
        },
        params=params,
        json=updates,
        timeout=15,
    )


def fetch_thresholds():
    """Fetch status thresholds for this company."""
    return _sb_get("status_thresholds", {
        "company_id": f"eq.{COMPANY_ID}",
        "select": "status_name,yellow_max_minutes,notification_delay_minutes",
    })


def fetch_directory_by_email():
    """Fetch directory entries keyed by email."""
    rows = _sb_get("directory", {
        "company_id": f"eq.{COMPANY_ID}",
        "active": "eq.true",
        "select": "id,email,first_name,last_name,manager_id,slack_user_id",
    })
    return {r["email"].lower(): r for r in rows if r.get("email")}


def fetch_slack_config():
    """Fetch company Slack bot token."""
    rows = _sb_get("company_settings", {
        "company_id": f"eq.{COMPANY_ID}",
        "select": "slack_bot_token",
    })
    return rows[0].get("slack_bot_token") if rows else None


def fetch_active_notification(agent_identifier, status_name):
    """Check for an active (not cleared) notification event."""
    rows = _sb_get("notification_events", {
        "company_id": f"eq.{COMPANY_ID}",
        "agent_identifier": f"eq.{agent_identifier}",
        "status_name": f"eq.{status_name}",
        "cleared_at": "is.null",
        "select": "id",
    })
    return rows[0] if rows else None


def send_slack_dm(token, email, message, slack_user_id=None):
    """Send a Slack DM to a user by email or slack_user_id."""
    if not token:
        return

    user_id = slack_user_id
    if not user_id and email:
        try:
            resp = requests.get(
                "https://slack.com/api/users.lookupByEmail",
                headers={"Authorization": f"Bearer {token}"},
                params={"email": email},
                timeout=10,
            )
            data = resp.json()
            if data.get("ok"):
                user_id = data["user"]["id"]
        except Exception:
            pass

    if not user_id:
        return

    try:
        requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"channel": user_id, "text": message},
            timeout=10,
        )
    except Exception as e:
        log.warning(f"Slack DM failed: {e}")


def fetch_infraction_type_for_status(status_name):
    """Map a threshold breach status to an infraction type."""
    status_lower = status_name.lower()
    code = None
    if "break" in status_lower or "lunch" in status_lower:
        code = "BREAK_VIOLATION"
    elif "not ready" in status_lower or "offline" in status_lower:
        code = "TARDY"
    else:
        code = "TARDY"

    rows = _sb_get("infraction_types", {
        "company_id": f"eq.{COMPANY_ID}",
        "code": f"eq.{code}",
        "select": "id,default_points",
    })
    return rows[0] if rows else None


def check_thresholds_and_notify(agents, user_mapping):
    """After writing snapshots, check thresholds and send notifications."""
    thresholds = fetch_thresholds()
    if not thresholds:
        return 0

    threshold_map = {}
    for t in thresholds:
        threshold_map[t["status_name"].lower()] = {
            "max_minutes": t["yellow_max_minutes"],
            "delay_minutes": t.get("notification_delay_minutes", 5),
        }

    directory = fetch_directory_by_email()
    slack_token = fetch_slack_config()
    notified_count = 0
    breaching_keys = set()

    for agent in agents:
        status = agent.get("status_name", "")
        duration_sec = agent.get("status_duration")
        if not status or duration_sec is None:
            continue

        threshold = threshold_map.get(status.lower())
        if not threshold:
            continue

        notify_after_minutes = threshold["max_minutes"] + threshold["delay_minutes"]
        duration_min = duration_sec / 60
        agent_id = agent.get("user_id", "")
        agent_email = user_mapping.get(agent_id, {}).get("email", "")

        breach_key = f"{agent_id}:{status}"
        breaching_keys.add(breach_key)

        if duration_min < notify_after_minutes:
            continue

        # Over threshold+grace — check if already notified
        existing = fetch_active_notification(agent_id, status)
        if existing:
            continue

        # Create notification event
        now_iso = datetime.now(timezone.utc).isoformat()
        notif_row = _sb_post("notification_events", {
            "company_id": COMPANY_ID,
            "agent_identifier": agent_id,
            "agent_email": agent_email,
            "status_name": status,
            "threshold_exceeded_at": now_iso,
            "notified_at": now_iso,
            "agent_notified": bool(slack_token),
            "manager_notified": bool(slack_token),
        })

        notif_id = notif_row[0]["id"] if notif_row else None

        # Send Slack DMs
        dir_entry = directory.get(agent_email.lower(), {})
        agent_name = f"{dir_entry.get('first_name', '')} {dir_entry.get('last_name', '')}".strip() or agent_email
        threshold_min = threshold["max_minutes"]
        dur_display = f"{int(duration_min)}m"

        if slack_token:
            send_slack_dm(
                slack_token,
                agent_email,
                f"You've been in {status} for {dur_display}. Threshold is {threshold_min}m.",
                dir_entry.get("slack_user_id"),
            )

            # DM manager
            manager_id = dir_entry.get("manager_id")
            if manager_id:
                manager_rows = _sb_get("directory", {
                    "id": f"eq.{manager_id}",
                    "select": "email,slack_user_id",
                })
                if manager_rows:
                    mgr = manager_rows[0]
                    send_slack_dm(
                        slack_token,
                        mgr.get("email"),
                        f"⚠️ {agent_name} has been in {status} for {dur_display} (threshold: {threshold_min}m)",
                        mgr.get("slack_user_id"),
                    )

        # Auto-create infraction
        person_id = dir_entry.get("id")
        if person_id:
            infraction_type = fetch_infraction_type_for_status(status)
            if infraction_type:
                _sb_post("infractions", {
                    "company_id": COMPANY_ID,
                    "person_id": person_id,
                    "infraction_type_id": infraction_type["id"],
                    "points": infraction_type["default_points"],
                    "occurred_at": now_iso,
                    "status_name": status,
                    "breach_duration_seconds": duration_sec,
                    "auto_detected": True,
                    "notification_event_id": notif_id,
                    "notes": f"Auto-detected: {status} for {dur_display} (threshold {threshold_min}m)",
                })

        notified_count += 1

    # Clear notifications for agents no longer in breach
    active_notifs = _sb_get("notification_events", {
        "company_id": f"eq.{COMPANY_ID}",
        "cleared_at": "is.null",
        "select": "id,agent_identifier,status_name",
    })

    for notif in active_notifs:
        key = f"{notif['agent_identifier']}:{notif['status_name']}"
        if key not in breaching_keys:
            _sb_patch(
                "notification_events",
                {"id": notif["id"]},
                {"cleared_at": datetime.now(timezone.utc).isoformat()},
            )

    return notified_count


# ── Flask endpoints ──────────────────────────────────────────

@app.route("/")
def health():
    return jsonify({"status": "ok", "service": "aws-connect-poller"})


@app.route("/debug")
def debug():
    """Return raw API response for one agent (for debugging)."""
    token = request.args.get("token", "")
    if POLL_SECRET and token != POLL_SECRET:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    client = boto3.client("connect", region_name=AWS_REGION)
    filters = get_filter_ids(client)
    resp = client.get_current_user_data(
        InstanceId=AWS_CONNECT_INSTANCE_ID, Filters=filters, MaxResults=1
    )
    # Convert datetimes to strings for JSON
    import copy
    data = copy.deepcopy(resp.get("UserDataList", []))
    for d in data:
        for key in ("Status", ):
            if key in d and "StatusStartTimestamp" in d[key]:
                d[key]["StatusStartTimestamp"] = d[key]["StatusStartTimestamp"].isoformat()
    return jsonify({"raw": data})


@app.route("/poll")
def poll():
    """Grab AWS Connect agent state snapshot and write to Supabase."""
    token = request.args.get("token", "")
    if POLL_SECRET and token != POLL_SECRET:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if not AWS_CONNECT_INSTANCE_ID:
        return jsonify({"ok": False, "error": "AWS_CONNECT_INSTANCE_ID not configured"}), 500

    if not COMPANY_ID:
        return jsonify({"ok": False, "error": "COMPANY_ID not configured"}), 500

    start = time.time()
    snapshot_ts = datetime.now(timezone.utc).isoformat()

    try:
        client = boto3.client("connect", region_name=AWS_REGION)
        user_mapping = get_user_mapping(client)
        rp_mapping = _rp_cache
        agents = poll_aws_connect(client)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    count, err = write_to_supabase(agents, snapshot_ts, user_mapping, rp_mapping)
    if err:
        return jsonify({"ok": False, "error": err}), 500

    # Check thresholds and send notifications
    notifications_sent = 0
    try:
        notifications_sent = check_thresholds_and_notify(agents, user_mapping)
    except Exception as e:
        log.warning(f"Notification check failed: {e}")

    # Purge snapshots older than 48 hours
    purged = 0
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    del_resp = requests.delete(
        f"{SUPABASE_URL}/rest/v1/aws_agent_snapshots?company_id=eq.{COMPANY_ID}&snapshot_ts=lt.{cutoff}",
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Prefer": "return=representation",
        },
        timeout=30,
    )
    if del_resp.status_code == 200:
        purged = len(del_resp.json())

    elapsed = round(time.time() - start, 2)
    return jsonify({
        "ok": True,
        "agents_total": len(agents),
        "agents_written": count,
        "notifications_sent": notifications_sent,
        "purged": purged,
        "snapshot_ts": snapshot_ts,
        "elapsed_sec": elapsed,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
