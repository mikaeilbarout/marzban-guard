#!/usr/bin/env bash
# marzban-guard central-service deploy/update script. Run this ON THE SERVER
# that will run the api/worker/Postgres/Redis stack (this can be the same
# host as Freemiga or a separate one — they don't share a database).
# Idempotent — safe to re-run for updates. The node-side collector is a
# separate, much smaller step — see docs/DEPLOYMENT.md section 2, it's
# per-Xray-node and needs its own SSH access to each node.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/marzban-guard}"
REPO_URL="${REPO_URL:-git@github.com:mikaeilbarout/marzban-guard.git}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
warn() { printf '\n\033[1;33m!!! %s\033[0m\n' "$1"; }
gen_urlsafe() { python3 -c "import secrets; print(secrets.token_urlsafe(32))"; }

# --- 1. Docker ---
if ! command -v docker >/dev/null 2>&1; then
  log "Docker not found — installing via get.docker.com"
  curl -fsSL https://get.docker.com | sh
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "The 'docker compose' plugin is missing. Install docker-compose-plugin and re-run." >&2
  exit 1
fi

# --- 2. Clone or update ---
if [ -d "$REPO_DIR/.git" ]; then
  log "Repo already present at $REPO_DIR — pulling latest"
  git -C "$REPO_DIR" fetch origin
  git -C "$REPO_DIR" pull --ff-only origin "$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD)"
else
  log "Cloning $REPO_URL to $REPO_DIR"
  mkdir -p "$(dirname "$REPO_DIR")"
  git clone "$REPO_URL" "$REPO_DIR"
fi
cd "$REPO_DIR"

# --- 3. .env ---
FIRST_RUN=false
if [ ! -f .env ]; then
  FIRST_RUN=true
  log "Creating .env from .env.example with generated secrets"
  cp .env.example .env
  sed -i "s#^POSTGRES_PASSWORD=.*#POSTGRES_PASSWORD=$(gen_urlsafe)#" .env
  sed -i "s#^INGEST_API_KEY=.*#INGEST_API_KEY=$(gen_urlsafe)#" .env
  sed -i "s#^ADMIN_API_KEY=.*#ADMIN_API_KEY=$(gen_urlsafe)#" .env
  sed -i "s#^GRAFANA_ADMIN_PASSWORD=.*#GRAFANA_ADMIN_PASSWORD=$(gen_urlsafe)#" .env

  read -rp "Marzban admin username for marzban-guard to use (MARZBAN_ADMIN_USERNAME): " mu
  read -rsp "Marzban admin password (MARZBAN_ADMIN_PASSWORD): " mp; echo
  sed -i "s#^MARZBAN_ADMIN_USERNAME=.*#MARZBAN_ADMIN_USERNAME=${mu:-change_me}#" .env
  sed -i "s#^MARZBAN_ADMIN_PASSWORD=.*#MARZBAN_ADMIN_PASSWORD=${mp:-change_me}#" .env

  read -rp "Wire this up to Freemiga now? Freemiga's SITE_BASE_URL (blank to skip): " shop_url
  if [ -n "$shop_url" ]; then
    shop_secret="$(gen_urlsafe)"
    sed -i "s#^SHOP_BASE_URL=.*#SHOP_BASE_URL=${shop_url}#" .env
    sed -i "s#^SHOP_WEBHOOK_SECRET=.*#SHOP_WEBHOOK_SECRET=${shop_secret}#" .env
    echo "SHOP_WEBHOOK_SECRET=$shop_secret" > /tmp/marzban-guard-shop-wiring.env
    echo "ADMIN_API_KEY=$(grep ^ADMIN_API_KEY= .env | cut -d= -f2)" >> /tmp/marzban-guard-shop-wiring.env
  fi
else
  log ".env already exists — leaving it untouched"
fi

# --- 4. config.yaml ---
if [ ! -f config/config.yaml ]; then
  log "Creating config/config.yaml from config.example.yaml"
  cp config/config.example.yaml config/config.yaml
  read -rp "Marzban panel base URL (config.marzban.base_url), e.g. https://panel.example.com:8000: " panel_url
  if [ -n "$panel_url" ]; then
    # Only the marzban.base_url placeholder — config.yaml also has an unrelated
    # shop_integration.base_url line that must not be touched by this substitution.
    sed -i "s#base_url: \"https://panel.example.com:8000\"#base_url: \"$panel_url\"#" config/config.yaml
  fi
  warn "config/config.yaml has default detection thresholds — they are starting
    points, not calibrated to your traffic. Consider setting
    security.mitigation.auto_block.enabled: false for the first few days
    (dry-run) and watching Grafana before trusting it to act automatically.
    See docs/DEPLOYMENT.md section 3 ('Rolling out safely')."
else
  log "config/config.yaml already exists — leaving it untouched"
fi

# --- 5. Bring up the stack ---
log "Starting postgres + redis"
docker compose up -d postgres redis

log "Running migrations"
docker compose run --rm migrate

log "Starting api + worker + prometheus + grafana"
docker compose up -d api worker prometheus grafana

sleep 3
log "Health check"
if command -v curl >/dev/null 2>&1; then
  curl -fsS http://localhost:8000/healthz && echo || warn "healthz check failed — check 'docker compose logs api'"
  curl -fsS http://localhost:8000/readyz && echo || warn "readyz check failed — check 'docker compose logs api worker'"
fi

docker compose ps

warn "Port 8000 (api) is exposed directly on this host with no TLS/reverse
  proxy bundled by this repo (by design — see docs/DEPLOYMENT.md, 'Firewall
  / network note'). Before pointing real node collectors at it:
    - put it behind the same nginx/Cloudflare TLS termination you use
      elsewhere, or
    - at minimum, firewall port 8000 to only the IPs of your Xray/Marzban
      nodes and your own admin IP."

if [ "$FIRST_RUN" = true ] && [ -f /tmp/marzban-guard-shop-wiring.env ]; then
  log "Freemiga wiring — add these to Freemiga's .env, then restart the app:"
  echo "  MARZBAN_GUARD_BASE_URL=http://<this-host>:8000   (or the TLS URL you put in front of it)"
  cat /tmp/marzban-guard-shop-wiring.env | sed 's/^/  /'
  rm /tmp/marzban-guard-shop-wiring.env
fi

echo
echo "Next: install the node-side collector on every Xray/Marzban node —"
echo "see docs/DEPLOYMENT.md section 2. Grafana: http://<this-host>:3000"
