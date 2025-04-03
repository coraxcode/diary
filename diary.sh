#!/usr/bin/env sh
###############################################################################
# diary.sh
#
# A secure, professional ("NASA-level") shell script to manage plain-text diary
# entries with the ".txt" extension. Each entry is hashed with SHA-256, and all
# actions are logged in a robust CSV file. The script enforces UTF-8 encoding,
# normalizes line endings to LF, and carefully checks that each file ends in
# ".txt".
#
# Features:
#   - Logs file size (bytes) immediately after the filename.
#   - SHA-256 hash is logged as the final column in the CSV.
#   - "search <pattern>" to find words in all .txt files (case-insensitive).
#   - "audit [objective]" to check integrity of all entries at once (hash match).
#   - "stats" to show total files, total size, and creation dates from logs.
#   - "logs" to view the CSV log in a secure, read-only manner.
#
# Commands:
#   create <filename.txt>             Create a new diary entry.
#   edit <filename.txt>               Edit an existing entry.
#   check <filename.txt>              Verify the SHA-256 hash of an entry.
#   backup <filename.txt>             Backup an entry to Diary/backup.
#   update <filename.txt>             Re-hash an entry changed outside the script.
#   update <oldname.txt> <newname.txt> Rename and re-hash an entry.
#   search <pattern>                  Search all .txt entries (case-insensitive).
#   audit [objective]                 Verify integrity of all .txt files at once.
#   stats                             Show file count, total size, creation dates.
#   logs                              View the CSV log of actions.
#   help                              Show usage instructions.
#
# Example usage:
#   ./diary.sh create daily_notes.txt
#   ./diary.sh edit daily_notes.txt
#   ./diary.sh check daily_notes.txt
#   ./diary.sh backup daily_notes.txt
#   ./diary.sh update daily_notes.txt
#   ./diary.sh update oldname.txt newname.txt
#   ./diary.sh search "urgent"
#   ./diary.sh audit "Nightly check"
#   ./diary.sh stats
#   ./diary.sh logs
#
# Make it executable:
#   chmod +x diary.sh
#
# Then run:
#   ./diary.sh <command> [arguments]
###############################################################################

###############################################################################
# Strict Shell Settings
###############################################################################
set -e  # Exit immediately if any command returns a non-zero status
set -u  # Treat references to unset variables as an error

# Some shells do not support pipefail, so we guard it:
if (set -o | grep -q pipefail 2>/dev/null); then
  set -o pipefail
fi

# Use a safe IFS (only split on newlines/tabs/spaces).
IFS="$(printf '\n\t ')"

# Restrict file creation permissions (owner only: rw).
umask 0077

###############################################################################
# Directory Structure
###############################################################################
DIARY_BASE="Diary"
ENTRIES_DIR="${DIARY_BASE}/entries"
LOG_DIR="${DIARY_BASE}/logs"
BACKUP_DIR="${DIARY_BASE}/backup"

# CSV file for logging (append-only)
LOG_FILE="${LOG_DIR}/diary_log.csv"

###############################################################################
# Editor & Hash Tools
###############################################################################
EDITOR="${EDITOR:-vi}"
if ! command -v "$EDITOR" >/dev/null 2>&1; then
  EDITOR="vi"
fi

HASH_CMD=""
HASH_PARSE=""
if command -v sha256sum >/dev/null 2>&1; then
  HASH_CMD="sha256sum"
  HASH_PARSE="cut -d ' ' -f1"
elif command -v openssl >/dev/null 2>&1; then
  HASH_CMD="openssl dgst -sha256"
  HASH_PARSE="sed 's/^.*= //'"
else
  echo "Error: Neither sha256sum nor openssl is available on this system." >&2
  exit 1
fi

###############################################################################
# Dependency Check
###############################################################################
check_dependencies() {
  required_cmds='date grep awk cut sed cp tail mkdir touch rm mv iconv cat wc sort head find printf'
  for cmd in $required_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: Required command '$cmd' not found in PATH." >&2
      exit 1
    fi
  done
}
check_dependencies

###############################################################################
# Ensure Directories Exist
###############################################################################
mkdir -p "${ENTRIES_DIR}" "${LOG_DIR}"

###############################################################################
# Helper Functions
###############################################################################
usage() {
  cat << EOF
Usage: $0 <command> [arguments]

Commands:
  create <filename.txt>                Create a new diary entry (must end in .txt).
  edit <filename.txt>                  Edit an existing diary entry.
  check <filename.txt>                 Verify the SHA-256 hash of an existing entry.
  backup <filename.txt>                Backup an entry to the Diary/backup directory.
  update <filename.txt>                Re-hash a file changed outside the script.
  update <oldname.txt> <newname.txt>   Rename and re-hash a file changed outside the script.
  search <pattern>                     Search all .txt files (case-insensitive, recursive).
  audit [objective]                    Check all .txt file integrity at once; optional objective.
  stats                                Show total file count, total size, and creation dates.
  logs                                 View the diary log (CSV).
  help                                 Show this help message.

EOF
  exit 1
}

# Validate that filename ends in .txt
validate_txt_extension() {
  filename="$1"
  case "$filename" in
    *.txt) : ;;  # OK
    *)
      echo "Error: '$filename' must end in '.txt'." >&2
      exit 1
      ;;
  esac
}

###############################################################################
# CSV Logging
#   Format: "timestamp","action","filename","size","objective","hash"
# - size: file size in bytes (or "N/A")
# - objective: can be an empty string or user-supplied text
# - hash: final column
###############################################################################
log_action() {
  # $1 = action
  # $2 = filename
  # $3 = size (or "N/A")
  # $4 = objective (or empty)
  # $5 = hash
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "\"${timestamp}\",\"${1}\",\"${2}\",\"${3}\",\"${4}\",\"${5}\"" >> "${LOG_FILE}"
}

# Compute SHA-256 hash of a file, capturing just the hash value.
compute_hash() {
  file="$1"
  hash_value="$(${HASH_CMD} "${file}" 2>/dev/null | eval "${HASH_PARSE}")"
  echo "${hash_value}"
}

# Get file size in bytes (portable approach)
get_file_size() {
  file="$1"
  wc -c < "${file}" 2>/dev/null
}

# Check existence of file in ENTRIES_DIR
check_file_exists() {
  file="$1"
  if [ ! -f "${ENTRIES_DIR}/${file}" ]; then
    echo "Error: File '${file}' not found in ${ENTRIES_DIR}/." >&2
    exit 1
  fi
}

# Normalize to LF, enforce UTF-8; exit on invalid encoding
normalize_utf8() {
  file="$1"
  tmpfile="${file}.tmp"

  # Convert CRLF to LF
  sed 's/\r$//' "${file}" > "${tmpfile}"

  # Attempt to re-encode to UTF-8. If invalid, script exits immediately.
  iconv -f UTF-8 -t UTF-8 "${tmpfile}" -o "${file}"

  rm -f -- "${tmpfile}"
}

###############################################################################
# Command Implementations
###############################################################################
create_entry() {
  filename="$1"
  validate_txt_extension "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  if [ -f "${filepath}" ]; then
    echo "Error: Diary entry '${filename}' already exists." >&2
    exit 1
  fi

  # Create file, then open in $EDITOR
  touch -- "${filepath}"
  "${EDITOR}" "${filepath}"

  normalize_utf8 "${filepath}"
  hash_value="$(compute_hash "${filepath}")"
  filesize="$(get_file_size "${filepath}")"

  # Log: "CREATE", filename, size, "", hash
  log_action "CREATE" "${filename}" "${filesize}" "" "${hash_value}"

  echo "Created new entry: ${filename}"
  echo "SHA-256: ${hash_value}"
  echo "File size (bytes): ${filesize}"
}

edit_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  "${EDITOR}" "${filepath}"

  normalize_utf8 "${filepath}"
  hash_value="$(compute_hash "${filepath}")"
  filesize="$(get_file_size "${filepath}")"

  # Log: "EDIT", filename, size, "", hash
  log_action "EDIT" "${filename}" "${filesize}" "" "${hash_value}"

  echo "Entry edited: ${filename}"
  echo "New SHA-256: ${hash_value}"
  echo "File size (bytes): ${filesize}"
}

check_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  current_hash="$(compute_hash "${filepath}")"

  # Last logged hash is column 6 in CSV:
  # "timestamp","action","filename","size","objective","hash"
  last_logged_hash="$(grep ",\"${filename}\"," "${LOG_FILE}" 2>/dev/null \
    | tail -n 1 \
    | awk -F, '{print $6}' \
    | tr -d '"')"

  if [ -z "${last_logged_hash}" ]; then
    echo "Warning: No previous hash found in log for '${filename}'."
    echo "Current SHA-256: ${current_hash}"
  else
    if [ "${current_hash}" = "${last_logged_hash}" ]; then
      echo "Integrity OK: Current hash matches the last logged hash."
      echo "SHA-256: ${current_hash}"
    else
      echo "WARNING: Hash mismatch detected!"
      echo "Current SHA-256:  ${current_hash}"
      echo "Last logged hash: ${last_logged_hash}"
    fi
  fi
}

backup_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  mkdir -p -- "${BACKUP_DIR}"

  src_path="${ENTRIES_DIR}/${filename}"
  dst_path="${BACKUP_DIR}/${filename}"

  cp -- "${src_path}" "${dst_path}"
  normalize_utf8 "${dst_path}"

  hash_original="$(compute_hash "${src_path}")"
  hash_copy="$(compute_hash "${dst_path}")"
  backup_size="$(get_file_size "${dst_path}")"

  if [ "${hash_original}" = "${hash_copy}" ]; then
    # Log: "BACKUP", filename, backup_size, "", hash_copy
    log_action "BACKUP" "${filename}" "${backup_size}" "" "${hash_copy}"

    echo "Backup successful: ${dst_path}"
    echo "SHA-256: ${hash_copy}"
    echo "Backup file size (bytes): ${backup_size}"
  else
    echo "ERROR: Backup verification failed! The copied file's hash differs."
    rm -f -- "${dst_path}"
    exit 1
  fi
}

update_entry() {
  # update <filename> | update <oldname> <newname>
  if [ $# -eq 1 ]; then
    # Re-hash only
    filename="$1"
    validate_txt_extension "${filename}"
    check_file_exists "${filename}"

    filepath="${ENTRIES_DIR}/${filename}"
    normalize_utf8 "${filepath}"

    new_hash="$(compute_hash "${filepath}")"
    new_size="$(get_file_size "${filepath}")"

    # Log: "UPDATE", filename, size, "", hash
    log_action "UPDATE" "${filename}" "${new_size}" "" "${new_hash}"

    echo "File '${filename}' updated."
    echo "New hash: ${new_hash}"
    echo "File size (bytes): ${new_size}"

  elif [ $# -eq 2 ]; then
    # Rename + re-hash
    oldname="$1"
    newname="$2"
    validate_txt_extension "${oldname}"
    validate_txt_extension "${newname}"

    oldpath="${ENTRIES_DIR}/${oldname}"
    newpath="${ENTRIES_DIR}/${newname}"

    if [ ! -f "${oldpath}" ]; then
      echo "Error: File '${oldname}' not found." >&2
      exit 1
    fi
    if [ -f "${newpath}" ]; then
      echo "Error: Cannot rename to '${newname}' (already exists)." >&2
      exit 1
    fi

    mv -- "${oldpath}" "${newpath}"
    normalize_utf8 "${newpath}"

    new_hash="$(compute_hash "${newpath}")"
    new_size="$(get_file_size "${newpath}")"

    # Log: "UPDATE", newname, size, "", hash
    log_action "UPDATE" "${newname}" "${new_size}" "" "${new_hash}"

    echo "File renamed from '${oldname}' to '${newname}'."
    echo "New hash: ${new_hash}"
    echo "File size (bytes): ${new_size}"
  else
    usage
  fi
}

search_entries() {
  # search <pattern>
  if [ $# -lt 1 ]; then
    echo "Error: 'search' requires a pattern." >&2
    usage
  fi

  pattern="$*"
  echo "Searching in: ${ENTRIES_DIR}"
  echo "Pattern (case-insensitive): '${pattern}'"

  # Recursively, case-insensitive search in *.txt files only.
  if ! grep -iRn -H --include='*.txt' "${pattern}" "${ENTRIES_DIR}" 2>/dev/null; then
    echo "No matches found."
  fi
}

audit_entries() {
  # audit [objective]
  objective="$*"
  [ -z "${objective}" ] && objective="No objective provided."

  echo "=== AUDIT: Verifying integrity of all .txt files in ${ENTRIES_DIR} ==="
  echo "Objective: ${objective}"

  mismatch_found=0
  mismatch_files=""

  # Loop through each .txt in ENTRIES_DIR
  for filepath in "${ENTRIES_DIR}"/*.txt; do
    [ ! -e "${filepath}" ] && continue  # skip if no .txt found

    filename="$(basename "${filepath}")"
    current_hash="$(compute_hash "${filepath}")"

    # Last logged hash is column 6 in CSV
    last_logged_hash="$(grep ",\"${filename}\"," "${LOG_FILE}" 2>/dev/null \
      | tail -n 1 \
      | awk -F, '{print $6}' \
      | tr -d '"')"

    if [ -z "${last_logged_hash}" ]; then
      echo "  [WARNING] ${filename}: No logged hash found (unlogged file?)."
      mismatch_found=1
      mismatch_files="${mismatch_files} ${filename}"
    else
      if [ "${current_hash}" != "${last_logged_hash}" ]; then
        echo "  [MISMATCH] ${filename}: current=${current_hash}, logged=${last_logged_hash}"
        mismatch_found=1
        mismatch_files="${mismatch_files} ${filename}"
      else
        echo "  [OK] ${filename}"
      fi
    fi
  done

  # Log overall AUDIT result
  if [ "${mismatch_found}" -eq 0 ]; then
    log_action "AUDIT" "ALL_FILES" "N/A" "${objective}" "ALL_MATCH"
    echo "=== AUDIT COMPLETE: ALL FILES MATCH ==="
  else
    log_action "AUDIT" "ALL_FILES" "N/A" "${objective}" "MISMATCH_DETECTED"
    echo "=== AUDIT COMPLETE: MISMATCHES FOUND in:${mismatch_files} ==="
  fi
}

stats_action() {
  echo "=== STATS: Overview of .txt files in ${ENTRIES_DIR} ==="
  files="$(find "${ENTRIES_DIR}" -maxdepth 1 -type f -name '*.txt' 2>/dev/null || true)"

  if [ -z "${files}" ]; then
    echo "No .txt files found in ${ENTRIES_DIR}."
    return
  fi

  total_files=0
  total_size=0

  # Print table header
  printf "%-30s %-12s %-25s\n" "FILENAME" "SIZE(bytes)" "CREATION_DATE(from log)"

  for f in ${files}; do
    filename="$(basename "${f}")"
    size="$(get_file_size "${f}")"
    total_size=$((total_size + size))
    total_files=$((total_files + 1))

    # Earliest "CREATE" line: "timestamp","CREATE","filename","size","objective","hash"
    creation_line="$(grep "\"CREATE\",\"${filename}\"" "${LOG_FILE}" 2>/dev/null | head -n 1)"
    if [ -n "${creation_line}" ]; then
      creation_date="$(echo "${creation_line}" | awk -F, '{print $1}' | sed 's/^"//; s/"$//')"
    else
      creation_date="Unknown"
    fi

    printf "%-30s %-12s %-25s\n" "${filename}" "${size}" "${creation_date}"
  done

  echo
  echo "Total .txt files: ${total_files}"
  echo "Total size (bytes): ${total_size}"
}

logs_action() {
  # Display the log file if it exists
  if [ ! -f "${LOG_FILE}" ]; then
    echo "No log entries found. ${LOG_FILE} does not exist."
  else
    echo "=== Diary Log (CSV) ==="
    cat -- "${LOG_FILE}"
  fi
}

###############################################################################
# Main Script Logic
###############################################################################
[ $# -lt 1 ] && usage

command="$1"
shift

case "${command}" in
  create)
    [ $# -ne 1 ] && { echo "Error: 'create' requires exactly 1 argument."; usage; }
    create_entry "$1"
    ;;
  edit)
    [ $# -ne 1 ] && { echo "Error: 'edit' requires exactly 1 argument."; usage; }
    edit_entry "$1"
    ;;
  check)
    [ $# -ne 1 ] && { echo "Error: 'check' requires exactly 1 argument."; usage; }
    check_entry "$1"
    ;;
  backup)
    [ $# -ne 1 ] && { echo "Error: 'backup' requires exactly 1 argument."; usage; }
    backup_entry "$1"
    ;;
  update)
    # Accepts 1 or 2 arguments
    [ $# -lt 1 ] && { echo "Error: 'update' requires 1 or 2 arguments."; usage; }
    update_entry "$@"
    ;;
  search)
    [ $# -lt 1 ] && { echo "Error: 'search' requires a pattern."; usage; }
    search_entries "$@"
    ;;
  audit)
    # Accepts 0 or more arguments
    audit_entries "$@"
    ;;
  stats)
    [ $# -gt 0 ] && { echo "Error: 'stats' does not accept extra arguments."; usage; }
    stats_action
    ;;
  logs)
    [ $# -gt 0 ] && { echo "Error: 'logs' does not accept extra arguments."; usage; }
    logs_action
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    echo "Error: Unknown command '${command}'." >&2
    usage
    ;;
esac

exit 0
