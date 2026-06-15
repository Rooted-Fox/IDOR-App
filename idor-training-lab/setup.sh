#!/usr/bin/env bash
# =============================================================================
# IDOR Training Lab — Local Setup Script
# =============================================================================
# Usage:  bash setup.sh [command]
# Commands:
#   install   — Create venvs and install dependencies
#   seed      — Populate databases with test data
#   run       — Start both apps (foreground, two terminals opened if possible)
#   stop      — Kill running lab processes
#   reset     — Wipe databases and re-seed
#   status    — Show what's running
#   (none)    — Full install + seed + run
# =============================================================================
set -e

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
VULN_DIR="$LAB_DIR/vulnerable_app"
SEC_DIR="$LAB_DIR/secure_app"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${BOLD}${CYAN}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║         IDOR Training Lab — Local Setup                  ║"
  echo "  ║  Vulnerable App: http://127.0.0.1:5001                   ║"
  echo "  ║  Secure App:     http://127.0.0.1:5002                   ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

check_python() {
  if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: python3 not found. Please install Python 3.10+${NC}"
    exit 1
  fi
  PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  echo -e "${GREEN}✓ Python $PY_VERSION found${NC}"
}

install() {
  echo -e "\n${BOLD}Installing dependencies...${NC}"
  check_python

  for dir in "$VULN_DIR" "$SEC_DIR"; do
    name=$(basename "$dir")
    echo -e "\n${CYAN}→ Setting up $name${NC}"
    if [ ! -d "$dir/venv" ]; then
      python3 -m venv "$dir/venv"
      echo "  Created virtual environment"
    fi
    "$dir/venv/bin/pip" install -q --upgrade pip
    "$dir/venv/bin/pip" install -q -r "$dir/requirements.txt"
    echo -e "  ${GREEN}✓ Dependencies installed${NC}"
  done
}

seed() {
  echo -e "\n${BOLD}Seeding databases...${NC}"
  cd "$VULN_DIR" && ./venv/bin/python seed_data.py
  cd "$SEC_DIR"  && ./venv/bin/python seed_data.py
  echo -e "${GREEN}✓ Both databases seeded${NC}"
}

run_apps() {
  echo -e "\n${BOLD}Starting applications...${NC}"
  echo -e "${YELLOW}⚠  The vulnerable app contains intentional security flaws.${NC}"
  echo -e "${YELLOW}   Use only in isolated, local environments.${NC}\n"

  # Start vulnerable app in background
  cd "$VULN_DIR"
  FLASK_ENV=development ./venv/bin/python app.py > /tmp/vuln_app.log 2>&1 &
  VULN_PID=$!
  echo -e "${RED}  [VULNERABLE]${NC} PID $VULN_PID → http://127.0.0.1:5001  (log: /tmp/vuln_app.log)"

  sleep 1

  # Start secure app in background
  cd "$SEC_DIR"
  SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  FLASK_ENV=development ./venv/bin/python app.py > /tmp/sec_app.log 2>&1 &
  SEC_PID=$!
  echo -e "${GREEN}  [SECURE]    ${NC} PID $SEC_PID → http://127.0.0.1:5002  (log: /tmp/sec_app.log)"

  echo -e "\n${BOLD}Both apps running. Press Ctrl+C to stop.${NC}"
  echo -e "  Tail logs:  tail -f /tmp/vuln_app.log /tmp/sec_app.log\n"

  # Save PIDs
  echo "$VULN_PID $SEC_PID" > /tmp/idor_lab_pids

  # Wait for Ctrl+C
  trap 'echo -e "\n${BOLD}Stopping...${NC}"; kill $VULN_PID $SEC_PID 2>/dev/null; rm -f /tmp/idor_lab_pids; exit 0' INT
  wait
}

stop() {
  if [ -f /tmp/idor_lab_pids ]; then
    read -r VULN_PID SEC_PID < /tmp/idor_lab_pids
    kill "$VULN_PID" "$SEC_PID" 2>/dev/null && echo -e "${GREEN}✓ Stopped both apps${NC}" || echo "Processes not running"
    rm -f /tmp/idor_lab_pids
  else
    pkill -f "vulnerable_app/app.py" 2>/dev/null || true
    pkill -f "secure_app/app.py"     2>/dev/null || true
    echo -e "${GREEN}✓ Stopped${NC}"
  fi
}

reset() {
  echo -e "\n${BOLD}Resetting databases...${NC}"
  rm -f "$VULN_DIR/vulnerable.db" "$SEC_DIR/secure.db"
  seed
  echo -e "${GREEN}✓ Databases reset${NC}"
}

status() {
  echo -e "\n${BOLD}Lab Status:${NC}"
  if pgrep -f "vulnerable_app/app.py" &>/dev/null; then
    echo -e "  ${RED}[VULNERABLE]${NC} Running → http://127.0.0.1:5001"
  else
    echo -e "  [VULNERABLE] Not running"
  fi
  if pgrep -f "secure_app/app.py" &>/dev/null; then
    echo -e "  ${GREEN}[SECURE]${NC}     Running → http://127.0.0.1:5002"
  else
    echo -e "  [SECURE]     Not running"
  fi
}

CMD="${1:-all}"
banner

case "$CMD" in
  install) install ;;
  seed)    seed ;;
  run)     run_apps ;;
  stop)    stop ;;
  reset)   reset ;;
  status)  status ;;
  all)     install; seed; run_apps ;;
  *)
    echo "Usage: $0 [install|seed|run|stop|reset|status]"
    exit 1
    ;;
esac
