#!/usr/bin/env bash
# Small CLI wrapper around the admin API's /api/v1/admin/users/* endpoints —
# for the day-to-day "unban this account", "what's its status", "who's
# riskiest right now" checks an admin does by hand. Run this ON THE SAME
# HOST as the api container (it talks to it over localhost), from anywhere —
# it locates the repo's .env relative to this script's own location.
#
# Usage:
#   scripts/mg-admin.sh status <username>
#   scripts/mg-admin.sh unban <username> [reason]
#   scripts/mg-admin.sh ban <username> <reason>
#   scripts/mg-admin.sh top-risk [limit]
#
# unban/ban go through the admin override endpoint, same as a manual
# reactivation from Marzban's own panel would NOT do correctly — this
# updates marzban-guard's own tracked status too, so future violations are
# still detected normally. See docs/ARCHITECTURE.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${MG_ENV_FILE:-$REPO_DIR/.env}"
BASE_URL="${MG_API_BASE_URL:-http://localhost:8000}"

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[ -f "$ENV_FILE" ] || { echo "Can't find .env at $ENV_FILE (set MG_ENV_FILE to override)." >&2; exit 1; }
API_KEY="$(grep '^ADMIN_API_KEY=' "$ENV_FILE" | cut -d '=' -f2-)"
[ -n "$API_KEY" ] || { echo "ADMIN_API_KEY is empty in $ENV_FILE" >&2; exit 1; }

api() {
  # api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -X "$method" -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
      -d "$body" "$BASE_URL$path"
  else
    curl -fsS -X "$method" -H "Authorization: Bearer $API_KEY" "$BASE_URL$path"
  fi
}

cmd_status() {
  local username="${1:?usage: mg-admin.sh status <username>}"
  api GET "/api/v1/admin/users/$username" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("username:  ", d["username"])
print("status:    ", d["status"])
print("reason:    ", d["status_reason"])
print("expires_at:", d["status_expires_at"])
print("last_seen: ", d["last_seen_at"])
print("score:     ", "%.1f" % d["risk_score"])
'
}

cmd_unban() {
  local username="${1:?usage: mg-admin.sh unban <username> [reason]}"
  local reason="${2:-manually reactivated by admin}"
  local body
  body=$(python3 -c 'import json,sys; print(json.dumps({"status":"active","reason":sys.argv[1],"actor":"admin-cli"}))' "$reason")
  api POST "/api/v1/admin/users/$username/override" "$body" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("OK -- %s is now %s" % (d["username"], d["status"]))
'
}

cmd_ban() {
  local username="${1:?usage: mg-admin.sh ban <username> <reason>}"
  local reason="${2:?usage: mg-admin.sh ban <username> <reason>}"
  local body
  body=$(python3 -c 'import json,sys; print(json.dumps({"status":"disabled","reason":sys.argv[1],"actor":"admin-cli"}))' "$reason")
  api POST "/api/v1/admin/users/$username/override" "$body" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("OK -- %s is now %s" % (d["username"], d["status"]))
'
}

cmd_top_risk() {
  local limit="${1:-20}"
  api GET "/api/v1/admin/users/top-risk?limit=$limit" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
if not rows:
    print("(no users tracked)")
    sys.exit(0)
w = max(len(r["username"]) for r in rows)
print("username".ljust(w), "     score", "status".ljust(12), "last_seen")
for r in rows:
    print(r["username"].ljust(w), "%10.1f" % r["risk_score"], r["status"].ljust(12), r["last_seen_at"])
'
}

case "${1:-}" in
  status)   shift; cmd_status "$@" ;;
  unban)    shift; cmd_unban "$@" ;;
  ban)      shift; cmd_ban "$@" ;;
  top-risk) shift; cmd_top_risk "$@" ;;
  *) usage ;;
esac
