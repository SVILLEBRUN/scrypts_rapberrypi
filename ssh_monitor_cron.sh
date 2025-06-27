#!/bin/bash

LOGFILE="/var/log/auth.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"
OUTPUT_LOG="$HOME/fail2ban/ssh-connection-attempts-test.log"
TRACKER_LOG="$HOME/fail2ban/.ssh_monitor_lastpos"
TRACKER_BAN="$HOME/fail2ban/.ssh_monitor_ban_lastpos"
NEW_LOGS_TEMP="$HOME/fail2ban/.new_logs_temp"

mkdir -p "$(dirname "$OUTPUT_LOG")"
touch "$OUTPUT_LOG"
touch "$NEW_LOGS_TEMP"

process_line_log() {
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
  echo "$output" >> "$NEW_LOGS_TEMP"
}

process_line_ban() {
  local ban_line="$1"
  local raw_date=$(echo "$ban_line" | grep -oP '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
  local ban_date=$(echo "$raw_date" | sed 's/ /T/')

  local ip=$(echo "$ban_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
  local jail=$(echo "$ban_line" | grep -oP 'NOTICE\s+\[\K[^\]]+')

  local status="BAN"
  local action="Banned"

  if echo "$ban_line" | grep -q "Ban "; then
    status="BAN"
    action="Banned"
  else
    status="UNBAN"
    action="Unbanned"
  fi

  output="[$ban_date] - $action - IP: $ip - Jail: $jail"
  echo "[$ban_date] - $action - IP: $ip - Jail: $jail" >> "$NEW_LOGS_TEMP"
}

# 1 - Reading new logs
CURRENT_SIZE_LOG=$(stat -c%s "$LOGFILE")
CURRENT_SIZE_BAN=$(stat -c%s "$FAIL2BAN_LOG")

if [[ "$1" == "--init" ]]; then
  LINES=100  # value by default
  if [[ "$2" =~ ^[0-9]+$ ]]; then
    LINES="$2"
  fi
  if [[ ! -f "$TRACKER_LOG" ]]; then
    REWIND_LOG=$(tail -n "$LINES" "$LOGFILE" | wc -c)
    LAST_POS_LOG=$((CURRENT_SIZE_LOG - REWIND_LOG))
    echo "$LAST_POS_LOG" > "$TRACKER_LOG"
  fi

  if [[ ! -f "$TRACKER_BAN" ]]; then
    REWIND_BAN=$(tail -n "$LINES" "$FAIL2BAN_LOG" | wc -c)
    LAST_POS_BAN=$((CURRENT_SIZE_BAN - REWIND_BAN))
    echo "$LAST_POS_BAN" > "$TRACKER_BAN"
  fi
fi

[[ -f "$TRACKER_LOG" ]] && LAST_POS_LOG=$(cat "$TRACKER_LOG") || LAST_POS_LOG=0

if (( LAST_POS_LOG > CURRENT_SIZE_LOG )); then
LAST_POS_LOG=0  # logrotate may have reset the file
fi

[[ -f "$TRACKER_BAN" ]] && LAST_POS_BAN=$(cat "$TRACKER_BAN") || LAST_POS_LOG=0

if (( LAST_POS_BAN > CURRENT_SIZE_BAN )); then
LAST_POS_BAN=0  # logrotate may have reset the file
fi

# Read lines that have not been read yet
if (( CURRENT_SIZE_LOG > LAST_POS_LOG )); then
  echo "Starting SSHD log reading ($LOGFILE)..."
  total_lines=$(tail -c +$((LAST_POS_LOG + 1)) "$LOGFILE" | grep -a -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" | wc -l)
  processed_lines=0

  tail -c +$((LAST_POS_LOG + 1)) "$LOGFILE" | grep -a -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" | while read -r line; do
    process_line_log "$line"

    processed_lines=$((processed_lines + 1))
    percent=$(( processed_lines * 100 / total_lines ))
    printf "\rProgress SSHD : %3d%% (processed lines : %d / %d)" "$percent" "$processed_lines" "$total_lines"
  done

  echo "$CURRENT_SIZE_LOG" > "$TRACKER_LOG"
  echo
  echo "End of SSHD log reading."
fi

if (( CURRENT_SIZE_BAN > LAST_POS_BAN )); then
  echo "Starting fail2ban log reading ($FAIL2BAN_LOG)..."
  total_lines_ban=$(tail -c +"$((LAST_POS_BAN + 1))" "$FAIL2BAN_LOG" | grep -a --line-buffered -E "Ban |Unban " | wc -l)
  processed_lines_ban=0

  tail -c +"$((LAST_POS_BAN + 1))" "$FAIL2BAN_LOG" | grep -a --line-buffered -E "Ban |Unban " |  while read -r line; do
    process_line_ban "$line"

    processed_lines_ban=$((processed_lines_ban + 1))
    percent_ban=$(( processed_lines_ban * 100 / total_lines_ban ))
    printf "\rProgress fail2ban : %3d%% (processed lines : %d / %d)" "$percent_ban" "$processed_lines_ban" "$total_lines_ban"
  done

  echo "$CURRENT_SIZE_BAN" > "$TRACKER_BAN"
  echo
  echo "End of fail2ban log reading."
fi

# Sort new lines by date
if [[ -s "$NEW_LOGS_TEMP" ]]; then
  SORTED_NEW="$NEW_LOGS_TEMP.sorted"
  sort -k1.2,1.20 "$NEW_LOGS_TEMP" -o "$SORTED_NEW"
  cat "$OUTPUT_LOG" "$SORTED_NEW" | sort -k1.2,1.20 -o "$OUTPUT_LOG"
  rm -f "$NEW_LOGS_TEMP" "$SORTED_NEW"
fi

