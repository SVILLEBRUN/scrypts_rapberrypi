#!/bin/bash

LOGFILE="/var/log/auth.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"

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
process_ssh() {
  local line="$1"
  local log_date=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')
  local ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
  local user=$(echo "$line" | grep -oP '(user|invalid user|for) \K\S+' | head -1)
  local status="INFO"
  local action="Info"

  if echo "$line" | grep -q "Failed password"; then status="FAIL"; action="Failed attempt"
  elif echo "$line" | grep -q "Invalid user"; then status="FAIL"; action="Invalid user"
  elif echo "$line" | grep -q "Accepted password"; then status="SUCCESS"; action="Successful password connection"
  elif echo "$line" | grep -q "Accepted publickey"; then status="SUCCESS"; action="Successful public key connection"
  elif echo "$line" | grep -q "Disconnected"; then status="INFO"; action="Disconnection"
  elif echo "$line" | grep -q "Received disconnect"; then status="INFO"; action="Received disconnection"
  elif echo "$line" | grep -q "error"; then status="FAIL"; action="SSH error"
  fi

  [[ -z "$user" ]] && user="N/A"
  [[ -z "$ip" ]] && ip="N/A"
  [[ -z "$log_date" ]] && log_date="N/A"

  echo -e "$(color "$status" "[$log_date] - $action - User: $user - IP: $ip")"
}

process_f2b() {
  local ban_line="$1"
  local ban_date=$(echo "$ban_line" | awk '{print $1, $2, $3}')
  local ip=$(echo "$ban_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
  local jail=$(echo "$ban_line" | grep -oP 'NOTICE\s+\[\K[^\]]+')

  if echo "$ban_line" | grep -q "Ban "; then
    status="BAN"; action="Banned"
  else
    status="UNBAN"; action="Unbanned"
  fi
  echo -e "$(color "$status" "[$ban_date] - $action - IP: $ip - Jail: $jail")"
}


# === ÉTAPE 0 : Affichage de l'historique (1 heure) ===
echo -e "\e[1;34m>>> Chargement de l'historique (dernière heure) <<<\e[0m"

# On définit le seuil de temps pour awk (Format ISO car utilisé dans process_ssh)
SSH_TIME_LIMIT=$(date -d '1 hour ago' +'%Y-%m-%dT%H:%M:%S')
F2B_TIME_LIMIT=$(date -d '1 hour ago' +'%Y-%m-%d %H:%M:%S')

{
  # On récupère SSH et on marque la ligne avec "TYPE_SSH"
  grep -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" "$LOGFILE" | \
  awk -v d="$SSH_TIME_LIMIT" '$1 >= d {print $1 " TYPE_SSH " $0}'

  # On récupère Fail2Ban, on remplace l'espace par un "T" pour le tri, et on marque avec "TYPE_F2B"
  grep -E "Ban |Unban " "$FAIL2BAN_LOG" | \
  awk -v d="$F2B_TIME_LIMIT" '$1" "$2 >= d {printf "%sT%s TYPE_F2B %s\n", $1, $2, $0}'
} | sort | while read -r line; do
  
  # On identifie le type de log pour appeler la bonne fonction
  if [[ "$line" == *"TYPE_SSH"* ]]; then
    # On retire le préfixe de tri avant de traiter
    process_ssh "${line#*TYPE_SSH }"
  elif [[ "$line" == *"TYPE_F2B"* ]]; then
    # On retire le préfixe de tri avant de traiter
    process_f2b "${line#*TYPE_F2B }"
  fi

done
# === Step 1 : continuous monitoring with tail -F ===

tail -Fn0 "$LOGFILE" | grep -a --line-buffered -E "sshd.*(Failed password|Invalid user|Disconnected|Accepted password|Accepted publickey|Received disconnect|error)" | while read -r line; do
  process_ssh "$line"
done &
AUTHLOG_PID=$!

# === Step 2 : monitoring of Fail2ban bans and unbans ===

tail -Fn0 "$FAIL2BAN_LOG" | grep -a --line-buffered -E "Ban |Unban " | while read -r ban_line; do
  process_f2b "$ban_line"
done &
FAIL2BAN_PID=$!

# === Step 3 : capture Ctrl+C and kill subprocesses ===
cleanup() {
  echo
  echo "Stop requested, killing processes..."
  kill  "$AUTHLOG_PID" "$FAIL2BAN_PID"
  bash "$HOME/fail2ban/ssh_monitor_cron.sh"
  exit 0
}

trap cleanup SIGINT

# === Step 4 : keep the script alive ===
wait "$AUTHLOG_PID"
wait "$FAIL2BAN_PID"
