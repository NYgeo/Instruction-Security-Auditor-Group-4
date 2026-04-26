#!/usr/bin/env bash
set -euo pipefail

## ---------------- CONFIG ----------------
LOG="${LOG:-log.txt}"
THRESH="${THRESH:-4}"

AUTH_LOG=""
SYS_LOG=""

## ---------------- HELPERS ----------------
ts() { date "+%Y-%m-%d %H:%M:%S"; }
log_event() { echo "[$(ts)] $1" >> "$LOG"; }

count_matching() {
  local pattern="$1"
  grep -cF -- "$pattern" "$LOG" 2>/dev/null || echo 0
}

already_banned() {
  local ip="$1"
  iptables -C INPUT -s "$ip" -j DROP 2>/dev/null
}

ban_ip() {
  local ip="$1"
  local reason="$2"
  if [[ -z "$ip" ]]; then
    return 0
  fi
  if already_banned "$ip"; then
    log_event "ALREADY_BANNED IP $ip ($reason)"
    return 0
  fi

  if iptables -I INPUT 1 -s "$ip" -j DROP 2>/dev/null; then
    log_event "BANNED IP $ip ($reason)"
  else
    log_event "BAN_FAILED IP $ip ($reason)"
  fi
}

pick_logs() {
  if [[ -r /var/log/auth.log ]]; then
    AUTH_LOG="/var/log/auth.log"
  elif [[ -r /var/log/secure ]]; then
    AUTH_LOG="/var/log/secure"
  else
    AUTH_LOG=""
  fi

  if [[ -r /var/log/syslog ]]; then
    SYS_LOG="/var/log/syslog"
  elif [[ -r /var/log/messages ]]; then
    SYS_LOG="/var/log/messages"
  else
    SYS_LOG=""
  fi
}

ensure_log_file() {
  touch "$LOG"
}

install_best_effort_iptables_log_rule() {
  # Rate-limited logging of inbound SYN packets (best-effort; may fail on some distros)
  iptables -C INPUT -p tcp --syn -m limit --limit 12/min --limit-burst 24 \
    -j LOG --log-prefix "IPTABLES: " --log-level 4 2>/dev/null || \
  iptables -I INPUT 1 -p tcp --syn -m limit --limit 12/min --limit-burst 24 \
    -j LOG --log-prefix "IPTABLES: " --log-level 4 2>/dev/null || true
}

## ---------------- DETECTORS ----------------
handle_failed_password() {
  local line="$1"
  local ip=""
  ip="$(awk '{for(i=1;i<=NF;i++) if($i=="from") {print $(i+1); exit}}' <<<"$line" || true)"

  log_event "FAILED_LOGIN from $ip"
  local c
  c="$(count_matching "FAILED_LOGIN from $ip")"
  if [[ -n "$ip" && "$c" -ge "$THRESH" ]]; then
    ban_ip "$ip" "FAILED_LOGIN"
  fi
}

handle_invalid_user() {
  local line="$1"
  local ip=""
  ip="$(awk '{for(i=1;i<=NF;i++) if($i=="from") {print $(i+1); exit}}' <<<"$line" || true)"

  log_event "INVALID_USER from $ip"
  local c
  c="$(count_matching "INVALID_USER from $ip")"
  if [[ -n "$ip" && "$c" -ge "$THRESH" ]]; then
    ban_ip "$ip" "INVALID_USER"
  fi
}

handle_sudo_attempt() {
  log_event "SUDO_ATTEMPT from LOCAL"
}

handle_priv_esc_attempt() {
  log_event "PRIV_ESC_ATTEMPT from LOCAL"
}

handle_iptables_event() {
  local line="$1"
  local src=""
  src="$(sed -n 's/.*SRC=\([^ ]*\).*/\1/p' <<<"$line" | head -n 1 || true)"

  log_event "IPTABLES_EVENT from $src"
  local c
  c="$(count_matching "IPTABLES_EVENT from $src")"
  if [[ -n "$src" && "$c" -ge "$THRESH" ]]; then
    ban_ip "$src" "IPTABLES_EVENT"
  fi
}

## ---------------- MONITORS ----------------
monitor_auth_log() {
  echo ""
  echo "=== [Part 2] AUTH LOG MONITOR ==="
  echo "File: ${AUTH_LOG}"

  tail -F "$AUTH_LOG" | while IFS= read -r line; do
    if grep -q "Failed password" <<<"$line"; then
      handle_failed_password "$line"
    fi
    if grep -q "Invalid user" <<<"$line"; then
      handle_invalid_user "$line"
    fi
    if grep -q "sudo" <<<"$line"; then
      handle_sudo_attempt
    fi
    if grep -E -q "su: .*FAILED|authentication failure" <<<"$line"; then
      handle_priv_esc_attempt
    fi
  done
}

monitor_sys_log() {
  echo ""
  echo "=== [Part 2] SYSLOG / IPTABLES MONITOR ==="
  echo "File: ${SYS_LOG}"

  tail -F "$SYS_LOG" | while IFS= read -r line; do
    if grep -q "IPTABLES:" <<<"$line"; then
      handle_iptables_event "$line"
    fi
  done
}

cleanup() {
  log_event "IDS STOP"
  # kill background tail pipelines started from this script
  kill 0 2>/dev/null || true
  exit 0
}

## ---------------- MAIN ----------------
echo "=== [Part 2] Detection Monitor ==="
echo "Log file: $LOG"
echo "Threshold: $THRESH"
echo "Note: run with sudo (needs /var/log + iptables)."

pick_logs
ensure_log_file
log_event "IDS START"
install_best_effort_iptables_log_rule

if [[ -z "${AUTH_LOG}" ]]; then
  echo "ERROR: No readable auth log found (tried /var/log/auth.log, /var/log/secure)."
  echo "       Run on a system with those logs, or adapt the script to use journald."
  exit 1
fi
if [[ -z "${SYS_LOG}" ]]; then
  echo "ERROR: No readable syslog found (tried /var/log/syslog, /var/log/messages)."
  echo "       Run on a system with those logs, or adapt the script to use journald."
  exit 1
fi

trap cleanup INT TERM

monitor_auth_log &
monitor_sys_log &
wait

