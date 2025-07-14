#!/usr/bin/env bash
# rotate_logs.sh
# Daily log rotation: copy and compress a specific log into a Year/Month archive structure.

# Configuration
ROOT_DIR="/var/log/alibaba"   # Root directory where log and archives reside
LOG_NAME="alibaba.log"         # Name of the log file to rotate

# Date components
YEAR=$(date +%Y)
MONTH=$(date +%b)   # Jan, Feb, Mar, ...
DAY=$(date +%d)

# Derived paths
LOG_FILE="$ROOT_DIR/$LOG_NAME"
ARCHIVE_YEAR_DIR="$ROOT_DIR/$YEAR"
ARCHIVE_MONTH_DIR="$ARCHIVE_YEAR_DIR/$MONTH"

# Ensure log file exists
if [[ ! -f "$LOG_FILE" ]]; then
  echo "[ERROR] Log file not found: $LOG_FILE" >&2
  exit 1
fi

# Create archive directories if missing
mkdir -p "$ARCHIVE_MONTH_DIR" || {
  echo "[ERROR] Failed to create archive dir: $ARCHIVE_MONTH_DIR" >&2
  exit 1
}

# Parse base name and extension
BASE_NAME="${LOG_NAME%.*}"      # e.g., alibaba
EXTENSION="${LOG_NAME##*.}"     # e.g., log
ARCHIVE_FILE="$ARCHIVE_MONTH_DIR/${BASE_NAME}-${DAY}.${EXTENSION}"

# Copy and compress
cp "$LOG_FILE" "$ARCHIVE_FILE" || {
  echo "[ERROR] Failed to copy $LOG_FILE to $ARCHIVE_FILE" >&2
  exit 1
}
gzip -f "$ARCHIVE_FILE" || {
  echo "[ERROR] Compression failed for $ARCHIVE_FILE" >&2
  exit 1
}

# Truncate original log
truncate -s 0 "$LOG_FILE"

echo "Rotated $LOG_NAME -> $ARCHIVE_MONTH_DIR/${BASE_NAME}-${DAY}.${EXTENSION}.gz"
