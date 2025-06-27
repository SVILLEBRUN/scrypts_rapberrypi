#!/bin/bash

# === CONFIGURATION ===
OUTPUT_DIR="$HOME/fail2ban"
LOG_OUTPUT="$OUTPUT_DIR/bans-history.log"
CACHE_FILE="$OUTPUT_DIR/.bans.cache"

# Create the directory if needed
mkdir -p "$OUTPUT_DIR"

# Create the log file if it doesn't exist
touch "$LOG_OUTPUT"

# Date of the current execution
NOW=$(date '+%Y-%m-%d %H:%M:%S')
TODAY=$(date '+%Y-%m-%d')

# Get all fail2ban logs (including archived ones)
LOGFILES=$(ls /var/log/fail2ban.log* 2>/dev/null)

# Temporary: store the banned IPs seen today
TMP_BANS=$(mktemp)

# Extract the lines containing "Ban"
for LOG in $LOGFILES; do
  if [[ "$LOG" == *.gz ]]; then
    zgrep 'Ban' "$LOG"
  else
    grep --text 'Ban' "$LOG"
  fi
done | awk '{print $0}' >> "$TMP_BANS"

# Extract the banned entries for each day
declare -A daily_bans
while IFS= read -r line; do
  date=$(echo "$line" | awk -F' ' '{print $1}')
  if [[ -n "$date" ]]; then
    if [[ -z "${daily_bans[$date]}" ]]; then
      daily_bans[$date]="$line"
    else
      daily_bans[$date]="${daily_bans[$date]}\n$line"
    fi
  fi
done < "$TMP_BANS"

# Write the results to the output file
for date in "${!daily_bans[@]}"; do
  if grep -q "=== $date" "$LOG_OUTPUT"; then
    # If yes, update the list of banned IPs for this date
    # Remove the old banned entries for this date
    sed -i "/=== $date/,/^$/d" "$LOG_OUTPUT"
  fi
  # Add the new banned entries
  {
    echo "=== $date ==="
    echo -e "${daily_bans[$date]}"
  } >> "$TMP_BANS.tmp"
done

# Add the new entries to the output file
cat "$TMP_BANS.tmp" >> "$LOG_OUTPUT"

# Cleanup
rm "$TMP_BANS"
rm "$TMP_BANS.tmp"
