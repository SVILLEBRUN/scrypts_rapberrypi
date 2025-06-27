#!/bin/bash

LOGFILE="/var/log/auth.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
OUTPUT_LOG="$HOME/fail2ban/ssh-connection-attempts.log"
TRACKER="$HOME/fail2ban/.ssh_monitor_lastpos"

mkdir -p "$(dirname "$TRACKER")"
touch "$OUTPUT_LOG"

color() {
  case "$1" in
    "FAIL") echo -e "\e[31m$2\e[0m" ;;
    "SUCCESS") echo -e "\e[32m$2\e[0m" ;;
    "INFO") echo -e "\e[36m$2\e[0m" ;;
    "BAN") echo -e "\e[38;5;208m$2\e[0m" ;;
    "UNBAN") echo -e "\e[33m$2\e[0m" ;;
    *) echo "$2" ;;
  esac
}

process_line() {
  local line="$1"

  local log_date=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
  local ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
  local user=$(echo "$line" | grep -oP '(user|invalid user|for) \K\S+' | head -1)

  local status="INFO"
  local action="Info"

  if echo "$line" | grep -q "Failed password"; then
    status="FAIL"
    action="Failed attempt"
  elif echo "$line" | grep -q "Invalid user"; then
    status="FAIL"
    action="Invalid user"
  elif echo "$line" | grep -q "Accepted password"; then
    status="SUCCESS"
    action="Successful password connection"
  elif echo "$line" | grep -q "Accepted publickey"; then
    status="SUCCESS"
    action="Successful public key connection"
  elif echo "$line" | grep -q "Disconnected"; then
    status="INFO"
    action="Disconnection"
  elif echo "$line" | grep -q "Received disconnect"; then
    status="INFO"
    action="Received disconnection"
  elif echo "$line" | grep -q "error"; then
    status="FAIL"
    action="SSH error"
  fi

  [[ -z "$user" ]] && user="N/A"
  [[ -z "$ip" ]] && ip="N/A"
  [[ -z "$log_date" ]] && log_date="N/A"

  local output="[$log_date] - $action - User: $user - IP: $ip"

  echo -e "$(color "$status" "$output")"
  echo "$output" >> "$OUTPUT_LOG"
}

# === Step 1 : read new lines not yet processed ===

CURRENT_SIZE=$(stat -c%s "$LOGFILE")
if [[ "$1" == "--init" ]]; then
  LINES=100  # default value
  if [[ "$2" =~ ^[0-9]+$ ]]; then
    LINES="$2"
  fi

  if [[ ! -f "$TRACKER" ]]; then
    REWIND=$(tail -n "$LINES" "$LOGFILE" | wc -c)
    LAST_POS=$((CURRENT_SIZE - REWIND))
    echo "$LAST_POS" > "$TRACKER"
  fi
fi

[[ -f "$TRACKER" ]] && LAST_POS=$(cat "$TRACKER") || LAST_POS=0

if (( LAST_POS > CURRENT_SIZE )); then
  LAST_POS=0  # logrotate may have reset the file
fi

# Read lines that have not been read yet
if (( CURRENT_SIZE > LAST_POS )); then
  tail -c +$((LAST_POS + 1)) "$LOGFILE" | grep -a -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" | while read -r line; do
    process_line "$line"
  done
fi

# Update the tracker after the initial read
stat -c%s "$LOGFILE" > "$TRACKER"

# === Step 2 : continuous monitoring with tail -F ===

tail -Fn0 "$LOGFILE" | grep -a --line-buffered -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" | while read -r line; do
  process_line "$line"
  stat -c%s "$LOGFILE" > "$TRACKER"
done &
AUTHLOG_PID=$!

# === Step 3 : monitoring of Fail2ban bans and unbans ===

tail -Fn0 "$FAIL2BAN_LOG" | grep -a --line-buffered -E "Ban |Unban " | while read -r ban_line; do
  ban_date=$(echo "$ban_line" | awk '{print $1, $2, $3}')
  ip=$(echo "$ban_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
  jail=$(echo "$ban_line" | grep -oP 'NOTICE\s+\[\K[^\]]+')

  if echo "$ban_line" | grep -q "Ban "; then
    status="BAN"
    action="Banned"
  else
    status="UNBAN"
    action="Unbanned"
  fi

  output="[$ban_date] - $action - IP: $ip - Jail: $jail"
  echo -e "$(color "$status" "$output")"
  echo "[$ban_date] - $action - IP: $ip - Jail: $jail" >> "$OUTPUT_LOG"
done &
FAIL2BAN_PID=$!

# === Step 4 : capture Ctrl+C and kill subprocesses ===
cleanup() {
  echo
  echo "Stop requested, killing processes..."
  kill  "$AUTHLOG_PID" "$FAIL2BAN_PID"
  exit 0
}

trap cleanup SIGINT

# === Step 4 : keep the script alive ===
wait "$AUTHLOG_PID"
wait "$FAIL2BAN_PID"
