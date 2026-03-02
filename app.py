"""AWS Connect Agent State Poller.

Polls AWS Connect API every 60 seconds for agent state snapshots.
Writes each snapshot to Supabase for WFM interval analysis.

Deployed on Render as a web service with a /poll endpoint
triggered by an external cron (cron-job.org) or Render cron job.
"""

import os
import json
import time
from datetime import datetime, timezone, timedelta

import boto3
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

# ── Config from environment ──────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
POLL_SECRET = os.environ.get("POLL_SECRET", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_CONNECT_INSTANCE_ID = os.environ.get("AWS_CONNECT_INSTANCE_ID", "")


# ── User mapping cache ────────────────────────────────────────
_user_cache = {}
_user_cache_ts = None
USER_CACHE_TTL = timedelta(minutes=10)


def refresh_user_cache(client):
    """Load all users from AWS Connect via list_users."""
    global _user_cache, _user_cache_ts

    mapping = {}
    next_token = None
    while True:
        kwargs = {"InstanceId": AWS_CONNECT_INSTANCE_ID}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = client.list_users(**kwargs)
        for u in resp.get("UserSummaryList", []):
            mapping[u["Id"]] = {"email": u.get("Username", "")}
        next_token = resp.get("NextToken")
        if not next_token:
            break

    _user_cache = mapping
    _user_cache_ts = datetime.now(timezone.utc)
    return mapping


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

            agents.append({
                "user_id": user.get("Id", ""),
                "status_name": status.get("StatusName", ""),
                "status_start_utc": status_start_iso,
                "status_duration": status_duration,
                "routing_profile": routing.get("Name", ""),
                "contacts": [
                    {
                        "id": c.get("ContactId", ""),
                        "channel": c.get("Channel", ""),
                        "state": c.get("AgentContactState", ""),
                        "queue": c.get("Queue", {}).get("Name", ""),
                    }
                    for c in contacts
                ],
            })

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return agents


def write_to_supabase(agents, snapshot_ts, user_mapping):
    """Write agent snapshot rows to Supabase."""
    rows = []
    for a in agents:
        info = user_mapping.get(a["user_id"], {})

        rows.append({
            "snapshot_ts": snapshot_ts,
            "user_id": a["user_id"],
            "agent_email": info.get("email", ""),
            "status_name": a["status_name"],
            "status_start_utc": a["status_start_utc"],
            "status_duration": a["status_duration"],
            "routing_profile": a["routing_profile"],
            "contacts": json.dumps(a["contacts"]) if a["contacts"] else None,
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


# ── Flask endpoints ──────────────────────────────────────────

@app.route("/")
def health():
    return jsonify({"status": "ok", "service": "aws-connect-poller"})


@app.route("/poll")
def poll():
    """Grab AWS Connect agent state snapshot and write to Supabase."""
    token = request.args.get("token", "")
    if POLL_SECRET and token != POLL_SECRET:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if not AWS_CONNECT_INSTANCE_ID:
        return jsonify({"ok": False, "error": "AWS_CONNECT_INSTANCE_ID not configured"}), 500

    start = time.time()
    snapshot_ts = datetime.now(timezone.utc).isoformat()

    try:
        client = boto3.client("connect", region_name=AWS_REGION)
        user_mapping = get_user_mapping(client)
        agents = poll_aws_connect(client)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    count, err = write_to_supabase(agents, snapshot_ts, user_mapping)
    if err:
        return jsonify({"ok": False, "error": err}), 500

    # Purge snapshots older than 48 hours
    purged = 0
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    del_resp = requests.delete(
        f"{SUPABASE_URL}/rest/v1/aws_agent_snapshots?snapshot_ts=lt.{cutoff}",
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
        "purged": purged,
        "snapshot_ts": snapshot_ts,
        "elapsed_sec": elapsed,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
