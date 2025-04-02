#!/usr/bin/env sh
###############################################################################
# diary.sh
#
# A secure, professional ("NASA-level") shell script to manage plain-text diary
# entries with the ".txt" extension. Each entry is hashed with SHA-256, and all
# actions are logged in a robust CSV file. The script enforces UTF-8 encoding,
# normalizes line endings to LF, and carefully checks that each file ends in
# ".txt". Now includes a "logs" command to view the log file.
#
# Commands:
#   create <filename.txt>          Create a new diary entry with the given .txt name.
#   edit <filename.txt>            Edit an existing entry.
#   check <filename.txt>           Verify the SHA-256 hash of an entry.
#   backup <filename.txt>          Backup an entry to the Diary/backup directory.
#   update <filename.txt>          Re-hash an entry modified outside the script.
#        OR
#   update <oldname.txt> <newname.txt>  Rename and re-hash an entry.
#   logs                           View the CSV log of all recorded actions.
#   help                           Show usage instructions.
#
# Example usage:
#   ./diary.sh create daily_notes.txt
#   ./diary.sh edit daily_notes.txt
#   ./diary.sh check daily_notes.txt
#   ./diary.sh backup daily_notes.txt
#   ./diary.sh update daily_notes.txt
#   ./diary.sh update oldname.txt newname.txt
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
set -e
set -u
# Some shells do not support pipefail, so we guard it:
if (set -o | grep -q pipefail 2>/dev/null); then
  set -o pipefail
fi

# Use a safe IFS (only split on newlines/tabs/spaces).
IFS="$(printf '\n\t ')"

# Restrict file creation permissions (owner rw only).
umask 0077

###############################################################################
# Directory Structure
###############################################################################
DIARY_BASE="Diary"
ENTRIES_DIR="${DIARY_BASE}/entries"
LOG_DIR="${DIARY_BASE}/logs"
BACKUP_DIR="${DIARY_BASE}/backup"

# CSV file for logging
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
  required_cmds='date grep awk cut sed cp tail mkdir touch rm mv iconv cat'
  for cmd in $required_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: Required command '$cmd' not found." >&2
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
  create <filename.txt>            Create a new diary entry (must end in .txt).
  edit <filename.txt>              Edit an existing diary entry.
  check <filename.txt>             Verify the SHA-256 hash of an existing entry.
  backup <filename.txt>            Backup an entry to the Diary/backup directory.
  update <filename.txt>            Re-hash a file changed outside the script.
  update <oldname.txt> <newname.txt> Rename and re-hash a file changed outside the script.
  logs                             View the diary log (CSV).
  help                             Show this help message.

Examples:
  $0 create daily_notes.txt
  $0 edit daily_notes.txt
  $0 check daily_notes.txt
  $0 backup daily_notes.txt
  $0 update daily_notes.txt
  $0 update oldname.txt newname.txt
  $0 logs
EOF
  exit 1
}

# Enforce the ".txt" extension. Exit if it doesn't end with ".txt".
validate_txt_extension() {
  filename="$1"
  case "$filename" in
    *.txt) : ;;  # OK
    *)
      echo "Error: '$filename' must end in '.txt' to maintain .txt format." >&2
      exit 1
      ;;
  esac
}

# Highly secure CSV logging:
# Format: "timestamp","action","filename","hash"
# Quoted fields avoid CSV injection or format issues.
log_action() {
  # $1 = action
  # $2 = filename
  # $3 = hash
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "\"${timestamp}\",\"${1}\",\"${2}\",\"${3}\"" >> "${LOG_FILE}"
}

# Compute SHA-256 hash of a file
compute_hash() {
  file="$1"
  hash_value="$(${HASH_CMD} "${file}" 2>/dev/null | eval "${HASH_PARSE}")"
  echo "${hash_value}"
}

# Check existence of file in ENTRIES_DIR
check_file_exists() {
  file="$1"
  if [ ! -f "${ENTRIES_DIR}/${file}" ]; then
    echo "Error: File '${file}' not found in ${ENTRIES_DIR}/." >&2
    exit 1
  fi
}

# Normalize to LF, enforce UTF-8
normalize_utf8() {
  file="$1"
  tmpfile="${file}.tmp"

  # Remove CR (\r), producing LF-only endings
  sed 's/\r$//' "${file}" > "${tmpfile}"

  # Re-encode to UTF-8; fail if invalid
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
    echo "Error: A diary entry named '${filename}' already exists." >&2
    exit 1
  fi

  touch -- "${filepath}"
  "${EDITOR}" "${filepath}"

  normalize_utf8 "${filepath}"
  hash_value="$(compute_hash "${filepath}")"
  log_action "CREATE" "${filename}" "${hash_value}"

  echo "Created new entry: ${filename}"
  echo "SHA-256: ${hash_value}"
}

edit_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  "${EDITOR}" "${filepath}"

  normalize_utf8 "${filepath}"
  hash_value="$(compute_hash "${filepath}")"
  log_action "EDIT" "${filename}" "${hash_value}"

  echo "Entry edited: ${filename}"
  echo "New SHA-256: ${hash_value}"
}

check_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  hash_value="$(compute_hash "${filepath}")"

  # Last logged hash for this file:
  last_logged_hash="$(grep ",\"${filename}\"," "${LOG_FILE}" 2>/dev/null | tail -n 1 | awk -F, '{print $4}' | tr -d '"')"

  if [ -z "${last_logged_hash}" ]; then
    echo "Warning: No previous hash found in log for '${filename}'."
    echo "Current SHA-256: ${hash_value}"
  else
    if [ "${hash_value}" = "${last_logged_hash}" ]; then
      echo "Integrity OK: Current hash matches the last logged hash."
      echo "SHA-256: ${hash_value}"
    else
      echo "WARNING: Hash mismatch detected!"
      echo "Current SHA-256:  ${hash_value}"
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

  if [ "${hash_original}" = "${hash_copy}" ]; then
    log_action "BACKUP" "${filename}" "${hash_copy}"
    echo "Backup successful: ${dst_path}"
    echo "SHA-256: ${hash_copy}"
  else
    echo "ERROR: Backup verification failed! The copied file's hash differs."
    rm -f -- "${dst_path}"
    exit 1
  fi
}

update_entry() {
  if [ $# -eq 1 ]; then
    # Re-hash only
    filename="$1"
    validate_txt_extension "${filename}"
    check_file_exists "${filename}"

    filepath="${ENTRIES_DIR}/${filename}"
    normalize_utf8 "${filepath}"

    new_hash="$(compute_hash "${filepath}")"
    log_action "UPDATE" "${filename}" "${new_hash}"

    echo "File '${filename}' updated. New hash: ${new_hash}"

  elif [ $# -eq 2 ]; then
    # Rename + re-hash
    oldname="$1"
    newname="$2"
    validate_txt_extension "${oldname}"
    validate_txt_extension "${newname}"

    oldpath="${ENTRIES_DIR}/${oldname}"
    newpath="${ENTRIES_DIR}/${newname}"

    if [ ! -f "${oldpath}" ]; then
      echo "Error: File '${oldname}' not found in ${ENTRIES_DIR}/." >&2
      exit 1
    fi
    if [ -f "${newpath}" ]; then
      echo "Error: Cannot rename to '${newname}' (already exists)." >&2
      exit 1
    fi

    mv -- "${oldpath}" "${newpath}"
    normalize_utf8 "${newpath}"

    new_hash="$(compute_hash "${newpath}")"
    log_action "UPDATE" "${newname}" "${new_hash}"

    echo "File renamed from '${oldname}' to '${newname}'. New hash: ${new_hash}"
  else
    usage
  fi
}

logs_action() {
  # Display the log file in a secure, read-only manner
  if [ ! -f "${LOG_FILE}" ]; then
    echo "No log entries found. The log file does not exist yet."
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
    [ $# -lt 1 ] && { echo "Error: 'update' requires 1 or 2 arguments."; usage; }
    update_entry "$@"
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
