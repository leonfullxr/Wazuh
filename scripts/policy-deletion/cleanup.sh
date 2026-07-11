#!/bin/bash
# cleanup.sh - Delete Wazuh alert/archive log files older than N days.
# Usage: run daily from cron, e.g.:
#   0 2 * * * /path/to/cleanup.sh >/dev/null 2>&1

# Set locale to ensure month names are in English
export LC_ALL=C

# Define the directory paths
ALERTS_DIR="/var/ossec/logs/alerts"
ARCHIVES_DIR="/var/ossec/logs/archives"

# Retention period in days (change according to your retention policy)
RETENTION_DAYS=30

# Calculate the cutoff date
CUTOFF_MONTH=$(date -d "${RETENTION_DAYS} days ago" +"%Y/%b")
DAY_PART=$(date -d "${RETENTION_DAYS} days ago" +"%d")

# Function to clean up files older than the retention period in a given
# directory with a given filename pattern
cleanup_old_files() {
  local DIR=$1
  local PATTERN=$2
  local EXTENSIONS=$3

  # Check if the directory exists
  if [ ! -d "$DIR" ]; then
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo "${TIMESTAMP} Error: Directory $DIR does not exist." >> /var/log/messages
    return 1
  fi

  # Iterate over each extension
  for EXT in $EXTENSIONS; do
    # Construct the file pattern to match
    FILE_PATTERN="${DIR}/${CUTOFF_MONTH}/${PATTERN}-${DAY_PART}.${EXT}"

    # Check if any files match the pattern
    if compgen -G "$FILE_PATTERN" >/dev/null; then
      # Remove the files that match the pattern
      rm -f $FILE_PATTERN
      TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
      echo "${TIMESTAMP} Files with extension .$EXT older than ${RETENTION_DAYS} days have been deleted in $DIR." >> /var/log/messages
    else
      TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
      echo "${TIMESTAMP} No files found with extension .$EXT matching the pattern $FILE_PATTERN in $DIR." >> /var/log/messages
    fi
  done
}

# Clean up old alert files
cleanup_old_files "$ALERTS_DIR" "ossec-alerts" "log log.sum json sum log.gz json.gz json.sum"

# Clean up old archive files
cleanup_old_files "$ARCHIVES_DIR" "ossec-archives" "log log.sum json sum log.gz json.gz json.sum"
