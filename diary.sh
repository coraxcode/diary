#!/usr/bin/env sh
###############################################################################
# diary.sh
#
# A secure, professional ("NASA-level") shell script to manage plain-text diary
# entries with the ".txt" extension. Each entry is hashed with SHA-512, and all
# actions are logged in a robust CSV file. The script enforces UTF-8 encoding,
# normalizes line endings to LF, and ensures that each file name meets strict
# validation criteria. Additional functionality includes compression and
# decompression of the Diary directory via tar using ZSTD compression and SHA-512
# verification.
#
# Features:
#   - Logs file size (bytes) immediately after the filename.
#   - SHA-512 hash is logged as the final column in the CSV.
#   - "search <pattern>" to find words in all .txt files (case-insensitive).
#   - "audit [objective]" to check integrity of all entries at once (hash match).
#   - "stats" to show total file count, total size, and creation dates from logs.
#   - "logs" to view the diary log (CSV) in a secure, read-only manner.
#   - "compress [archive_file]" to compress the Diary directory using tar & ZSTD;
#       Produces an archive and a corresponding SHA-512 hash file.
#   - "decompress <archive_file>" to verify and decompress the provided Diary archive.
#   - "rename <oldname.txt> <newname.txt>" to rename and re-hash an entry.
#   - "delete <filename.txt>" to securely delete a diary entry (confirmation required).
#   - "encrypt <filename.txt>" to encrypt a diary entry using GPG.
#   - "decrypt <filename.txt>" to decrypt a diary entry using GPG.
#   - "update <filename.txt>" to re-hash a file changed outside the script.
#   - "updateall" to update (re-hash) all .txt diary entries.
#
# Commands:
#   create <filename.txt>             Create a new diary entry.
#   edit <filename.txt>               Edit an existing diary entry.
#   check <filename.txt>              Verify the SHA-512 hash of an entry.
#   backup <filename.txt>             Backup an entry to the Diary/backup directory.
#   update <filename.txt>             Re-hash a file changed outside the script.
#   rename <oldname.txt> <newname.txt>  Rename and re-hash an entry.
#   search <pattern>                  Search all .txt entries (case-insensitive).
#   audit [objective]                 Verify integrity of all .txt files at once.
#   stats                             Show total file count, total size, and creation dates.
#   logs                              View the diary log (CSV).
#   compress [archive_file]           Compress the entire Diary directory using tar & ZSTD.
#   decompress <archive_file>         Verify and decompress the provided Diary archive.
#   delete <filename.txt>             Securely delete a diary entry (confirmation required).
#   encrypt <filename.txt>            Encrypt a diary entry using GPG.
#   decrypt <filename.txt>            Decrypt a diary entry using GPG.
#   updateall                         Update (re-hash) all .txt diary entries.
#   help                              Show this help message.
#
# Example usage:
#   ./diary.sh create daily_notes.txt
#   ./diary.sh edit daily_notes.txt
#   ./diary.sh check daily_notes.txt
#   ./diary.sh backup daily_notes.txt
#   ./diary.sh update daily_notes.txt
#   ./diary.sh rename oldname.txt newname.txt
#   ./diary.sh search "urgent"
#   ./diary.sh audit "Nightly check"
#   ./diary.sh stats
#   ./diary.sh logs
#   ./diary.sh compress [optional_archive_name.tar.zst]
#   ./diary.sh decompress archive_name.tar.zst
#   ./diary.sh delete daily_notes.txt
#   ./diary.sh encrypt daily_notes.txt
#   ./diary.sh decrypt daily_notes.txt
#   ./diary.sh updateall
#
# Make it executable:
#   chmod +x diary.sh
#
# Then run:
#   ./diary.sh <command> [arguments]
###############################################################################
# Recommendation
# For enhanced security when compressing files, we recommend using a password-protected compression method. To achieve this, execute the following commands:
#
# To compress the files with password protection:
# 7z a -t7z -mhe=on -p archives_secure.7z archives/
#
# To extract the compressed archive:
# 7z x archive_secure.7z
#
# Please ensure that the password (YOUR_PASSWORD) is stored securely and is not disclosed in unsecured environments.
###############################################################################
# Strict Shell Settings
###############################################################################
set -e  # Exit immediately if any command returns a non-zero status.
set -u  # Treat references to unset variables as an error.

if (set -o | grep -q pipefail 2>/dev/null); then
  set -o pipefail
fi

IFS="$(printf '\n\t ')"
umask 0077

###############################################################################
# Directory Structure
###############################################################################
DIARY_BASE="Diary"
ENTRIES_DIR="${DIARY_BASE}/entries"
LOG_DIR="${DIARY_BASE}/logs"
BACKUP_DIR="${DIARY_BASE}/backup"

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
if command -v sha512sum >/dev/null 2>&1; then
  HASH_CMD="sha512sum"
  HASH_PARSE="cut -d ' ' -f1"
elif command -v openssl >/dev/null 2>&1; then
  HASH_CMD="openssl dgst -sha512"
  HASH_PARSE="sed 's/^.*= //'"
else
  echo "Error: Neither sha512sum nor openssl is available on this system." >&2
  exit 1
fi

###############################################################################
# Dependency Check
###############################################################################
check_dependencies() {
  required_cmds='date grep awk cut sed cp tail mkdir touch rm mv iconv cat wc sort head find printf tar shred mktemp gpg'
  for cmd in $required_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: Required command '$cmd' not found in PATH." >&2
      exit 1
    fi
  done
}
check_dependencies

###############################################################################
# Input Validation Functions
###############################################################################
validate_txt_extension() {
  filename="$1"
  if ! printf "%s" "$filename" | grep -Eq '^[A-Za-z0-9._-]+\.txt$'; then
    echo "Error: Invalid diary entry filename '$filename'. Allowed characters: A-Za-z0-9, ., -, _; and must end with .txt" >&2
    exit 1
  fi
}

validate_archive_filename() {
  archive="$1"
  if ! printf "%s" "$archive" | grep -Eq '^[A-Za-z0-9._-]+\.tar\.zst$'; then
    echo "Error: Invalid archive filename '$archive'. Allowed characters: A-Za-z0-9, ., -, _; and must end with .tar.zst" >&2
    exit 1
  fi
}

###############################################################################
# Helper Functions
###############################################################################
usage() {
  cat << EOF
Usage: $0 <command> [arguments]

Commands:
  create <filename.txt>                Create a new diary entry.
  edit <filename.txt>                  Edit an existing diary entry.
  check <filename.txt>                 Verify the SHA-512 hash of an entry.
  backup <filename.txt>                Backup an entry to the Diary/backup directory.
  update <filename.txt>                Re-hash a file changed outside the script.
  rename <oldname.txt> <newname.txt>   Rename and re-hash an entry.
  search <pattern>                     Search all .txt entries (case-insensitive).
  audit [objective]                    Verify integrity of all .txt files at once.
  stats                                Show total file count, total size, and creation dates.
  logs                                 View the diary log (CSV).
  compress [archive_file]              Compress the entire Diary directory using tar & ZSTD.
  decompress <archive_file>            Verify and decompress the provided Diary archive.
  delete <filename.txt>                Securely delete a diary entry (confirmation required).
  encrypt <filename.txt>               Encrypt a diary entry using GPG.
  decrypt <filename.txt>               Decrypt a diary entry using GPG.
  updateall                          Update (re-hash) all .txt diary entries.
  help                                 Show this help message.

EOF
  exit 1
}

log_action() {
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "\"${timestamp}\",\"${1}\",\"${2}\",\"${3}\",\"${4}\",\"${5}\"" >> "${LOG_FILE}"
}

compute_hash() {
  file="$1"
  hash_value="$(${HASH_CMD} "${file}" 2>/dev/null | eval "${HASH_PARSE}")"
  echo "${hash_value}"
}

get_file_size() {
  file="$1"
  wc -c < "${file}" 2>/dev/null
}

check_file_exists() {
  file="$1"
  if [ ! -f "${ENTRIES_DIR}/${file}" ]; then
    echo "Error: File '${file}' not found in ${ENTRIES_DIR}/." >&2
    exit 1
  fi
}

normalize_utf8() {
  file="$1"
  tmpfile="${file}.tmp"
  sed 's/\r$//' "${file}" > "${tmpfile}"
  iconv -f UTF-8 -t UTF-8 "${tmpfile}" -o "${file}"
  rm -f -- "${tmpfile}"
}

###############################################################################
# Compression & Decompression Functions
###############################################################################
compress_diary() {
  if ! command -v zstd >/dev/null 2>&1; then
    echo "Error: 'zstd' is required for compression but is not installed." >&2
    exit 1
  fi

  if [ "$#" -gt 1 ]; then
    echo "Error: 'compress' accepts at most one argument (the output archive file name)." >&2
    usage
  fi

  archive_file="${1:-}"
  if [ -n "${archive_file}" ]; then
    validate_archive_filename "${archive_file}"
  else
    timestamp="$(date '+%Y%m%dT%H%M%S')"
    archive_file="Diary_archive_${timestamp}.tar.zst"
  fi

  # If the archive file already exists, generate an alternative name with a random number.
  if [ -e "${archive_file}" ]; then
    timestamp="$(date '+%Y%m%dT%H%M%S')"
    random=$(printf "%04d" $((RANDOM % 10000)))
    archive_file="Diary_archive_${timestamp}_${random}.tar.zst"
  fi

  echo "Compressing '${DIARY_BASE}' into '${archive_file}' using tar and zstd..."
  tar -cf - "${DIARY_BASE}" | zstd -T0 -o "${archive_file}"
  if [ $? -ne 0 ]; then
    echo "Error: Compression failed." >&2
    exit 1
  fi

  archive_hash="$(compute_hash "${archive_file}")"
  hash_file="${archive_file}.sha512"
  echo "${archive_hash}" > "${hash_file}"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to write SHA-512 hash file." >&2
    exit 1
  fi

  echo "Compression complete."
  echo "Archive: ${archive_file}"
  echo "SHA-512 hash stored in: ${hash_file}"
}

decompress_diary() {
  if ! command -v zstd >/dev/null 2>&1; then
    echo "Error: 'zstd' is required for decompression but is not installed." >&2
    exit 1
  fi

  if [ "$#" -ne 1 ]; then
    echo "Error: 'decompress' requires exactly one argument: the archive file." >&2
    usage
  fi

  archive_file="$1"
  validate_archive_filename "${archive_file}"

  if [ ! -f "${archive_file}" ]; then
    echo "Error: Archive file '${archive_file}' not found." >&2
    exit 1
  fi

  hash_file="${archive_file}.sha512"
  if [ ! -f "${hash_file}" ]; then
    echo "Error: SHA-512 hash file '${hash_file}' not found; cannot verify integrity." >&2
    exit 1
  fi

  echo "Verifying integrity of '${archive_file}'..."
  computed_hash="$(compute_hash "${archive_file}")"
  stored_hash="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "${hash_file}")"
  
  if [ "${computed_hash}" != "${stored_hash}" ]; then
    echo "Warning: SHA-512 verification failed! Proceeding with extraction." >&2
    log_action "DECOMPRESS" "${archive_file}" "N/A" "SHA512 mismatch" "${computed_hash}"
  else
    echo "Integrity check passed."
  fi

  # If the DIARY_BASE directory already exists, extract to a new directory with an alternative name.
  if [ -d "${DIARY_BASE}" ]; then
    timestamp="$(date '+%Y%m%dT%H%M%S')"
    random=$(printf "%04d" $((RANDOM % 10000)))
    new_dir="Diary_archive_${timestamp}_${random}"
    echo "Target directory '${DIARY_BASE}' exists. Extracting archive into '${new_dir}' instead..."
    tar --xform "s,^${DIARY_BASE},${new_dir}," -I zstd -xf "${archive_file}"
    if [ $? -ne 0 ]; then
      echo "Error: Decompression failed." >&2
      exit 1
    fi
    echo "Decompression complete. Directory extracted as '${new_dir}'."
  else
    echo "Extracting '${archive_file}'..."
    tar -I zstd -xf "${archive_file}"
    if [ $? -ne 0 ]; then
      echo "Error: Decompression failed." >&2
      exit 1
    fi
    echo "Decompression complete. The '${DIARY_BASE}' directory has been restored."
  fi
}

###############################################################################
# Encrypt & Decrypt Functions (Improved version)
###############################################################################
encrypt_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  filepath="${ENTRIES_DIR}/${filename}"
  if [ ! -f "${filepath}" ]; then
    echo "Error: File '${filename}' not found." >&2
    exit 1
  fi
  # Read passphrase
  stty -echo
  printf "Enter encryption passphrase: "
  read passw
  stty echo
  printf "\n"
  gpg --batch --yes --passphrase "${passw}" --pinentry-mode loopback -c "${filepath}"
  if [ $? -ne 0 ]; then
    echo "Error: Encryption failed." >&2
    unset passw
    exit 1
  fi
  unset passw
  log_action "ENCRYPT" "${filename}" "$(get_file_size "${filepath}")" "" "ENCRYPTED"
  echo "File '${filename}' encrypted successfully. Encrypted file: '${filepath}.gpg'"
}

decrypt_entry() {
  # Allow the user to specify either the base name (ending in .txt) or the encrypted
  # name (ending in .txt.gpg). If the argument ends with .gpg, strip the extension.
  filename="$1"
  case "$filename" in
    *.gpg)
      filename="${filename%.gpg}"
      ;;
  esac
  validate_txt_extension "${filename}"
  encrypted_file="${ENTRIES_DIR}/${filename}.gpg"
  if [ ! -f "${encrypted_file}" ]; then
    echo "Error: Encrypted file '${filename}.gpg' not found." >&2
    exit 1
  fi
  # Read passphrase silently using read -s and then unset it
  printf "Enter decryption passphrase: "
  stty -echo
  read passw
  stty echo
  printf "\n"
  output_file="${ENTRIES_DIR}/${filename}"
  gpg --batch --yes --passphrase "${passw}" --pinentry-mode loopback -o "${output_file}" -d "${encrypted_file}"
  if [ $? -ne 0 ]; then
    echo "Error: Decryption failed. Bad session key or incorrect passphrase." >&2
    unset passw
    exit 1
  fi
  unset passw
  normalize_utf8 "${output_file}"
  log_action "DECRYPT" "${filename}" "$(get_file_size "${output_file}")" "" "DECRYPTED"
  echo "File '${filename}.gpg' decrypted successfully and restored to '${filename}'."
}

###############################################################################
# Remaining Command Implementations
###############################################################################
create_entry() {
  filename="$1"
  validate_txt_extension "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  if [ -f "${filepath}" ]; then
    echo "Error: Diary entry '${filename}' already exists." >&2
    exit 1
  fi

  touch -- "${filepath}"
  "${EDITOR}" "${filepath}"

  normalize_utf8 "${filepath}"
  hash_value="$(compute_hash "${filepath}")"
  filesize="$(get_file_size "${filepath}")"

  log_action "CREATE" "${filename}" "${filesize}" "" "${hash_value}"
  echo "Created new entry: ${filename}"
  echo "SHA-512: ${hash_value}"
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

  log_action "EDIT" "${filename}" "${filesize}" "" "${hash_value}"
  echo "Entry edited: ${filename}"
  echo "New SHA-512: ${hash_value}"
  echo "File size (bytes): ${filesize}"
}

check_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"

  filepath="${ENTRIES_DIR}/${filename}"
  current_hash="$(compute_hash "${filepath}")"

  last_logged_hash="$(grep ",\"${filename}\"," "${LOG_FILE}" 2>/dev/null | tail -n 1 | awk -F, '{print $6}' | tr -d '"')"

  if [ -z "${last_logged_hash}" ]; then
    echo "Warning: No previous hash found in log for '${filename}'."
    echo "Current SHA-512: ${current_hash}"
  else
    if [ "${current_hash}" = "${last_logged_hash}" ]; then
      echo "Integrity OK: Current hash matches the last logged hash."
      echo "SHA-512: ${current_hash}"
    else
      echo "WARNING: Hash mismatch detected!"
      echo "Current SHA-512: ${current_hash}"
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
    log_action "BACKUP" "${filename}" "${backup_size}" "" "${hash_copy}"
    echo "Backup successful: ${dst_path}"
    echo "SHA-512: ${hash_copy}"
    echo "Backup file size (bytes): ${backup_size}"
  else
    echo "ERROR: Backup verification failed! The copied file's hash differs."
    rm -f -- "${dst_path}"
    exit 1
  fi
}

update_entry() {
  if [ $# -eq 1 ]; then
    filename="$1"
    validate_txt_extension "${filename}"
    check_file_exists "${filename}"

    filepath="${ENTRIES_DIR}/${filename}"
    normalize_utf8 "${filepath}"
    new_hash="$(compute_hash "${filepath}")"
    new_size="$(get_file_size "${filepath}")"

    log_action "UPDATE" "${filename}" "${new_size}" "" "${new_hash}"
    echo "File '${filename}' updated."
    echo "New hash: ${new_hash}"
    echo "File size (bytes): ${new_size}"
  else
    echo "Error: 'update' requires exactly 1 argument." >&2
    usage
  fi
}

rename_entry() {
  if [ "$#" -ne 2 ]; then
    echo "Error: 'rename' requires exactly 2 arguments." >&2
    usage
  fi
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

  log_action "RENAME" "${newname}" "${new_size}" "" "${new_hash}"
  echo "File renamed from '${oldname}' to '${newname}'."
  echo "New SHA-512: ${new_hash}"
  echo "File size (bytes): ${new_size}"
}

delete_entry() {
  filename="$1"
  validate_txt_extension "${filename}"
  check_file_exists "${filename}"
  filepath="${ENTRIES_DIR}/${filename}"
  echo "Are you sure you want to permanently delete '${filename}'? Press ENTER to confirm or Ctrl+C to cancel."
  read -r dummy
  echo "Securely deleting '${filename}' using shred..."
  shred -n 10 -z -u -v "${filepath}"
  if [ $? -ne 0 ]; then
    echo "Error: Secure deletion failed for '${filename}'." >&2
    exit 1
  fi
  log_action "DELETE" "${filename}" "0" "" "DELETED"
  echo "File '${filename}' securely deleted."
}

update_all_entries() {
  echo "Updating all diary entries in '${ENTRIES_DIR}'..."
  count=0
  for file in "${ENTRIES_DIR}"/*.txt; do
    [ ! -f "${file}" ] && continue
    normalize_utf8 "${file}"
    new_hash="$(compute_hash "${file}")"
    new_size="$(get_file_size "${file}")"
    filename="$(basename "${file}")"
    log_action "UPDATEALL" "${filename}" "${new_size}" "" "${new_hash}"
    echo "Updated: ${filename} | SHA-512: ${new_hash}"
    count=$((count + 1))
  done
  echo "Total files updated: ${count}"
}

search_entries() {
  if [ $# -lt 1 ]; then
    echo "Error: 'search' requires a pattern." >&2
    usage
  fi

  pattern="$*"
  echo "Searching in: ${ENTRIES_DIR}"
  echo "Pattern (case-insensitive): '${pattern}'"
  if ! grep -iRn -H --include='*.txt' "${pattern}" "${ENTRIES_DIR}" 2>/dev/null; then
    echo "No matches found."
  fi
}

audit_entries() {
  objective="$*"
  [ -z "${objective}" ] && objective="No objective provided."
  echo "=== AUDIT: Verifying integrity of all .txt files in ${ENTRIES_DIR} ==="
  echo "Objective: ${objective}"
  mismatch_found=0
  mismatch_files=""

  for filepath in "${ENTRIES_DIR}"/*.txt; do
    [ ! -e "${filepath}" ] && continue
    filename="$(basename "${filepath}")"
    current_hash="$(compute_hash "${filepath}")"
    last_logged_hash="$(grep ",\"${filename}\"," "${LOG_FILE}" 2>/dev/null | tail -n 1 | awk -F, '{print $6}' | tr -d '"')"

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
  printf "%-30s %-12s %-25s\n" "FILENAME" "SIZE(bytes)" "CREATION_DATE(from log)"

  for f in ${files}; do
    filename="$(basename "${f}")"
    size="$(get_file_size "${f}")"
    total_size=$((total_size + size))
    total_files=$((total_files + 1))
    creation_line="$(grep "\"CREATE\",\"${filename}\"" "${LOG_FILE}" 2>/dev/null | head -n 1)"
    if [ -n "${creation_line}" ]; then
      creation_date="$(echo "${creation_line}" | awk -F, '{print $1}' | sed 's/^"//;s/"$//')"
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

# For all commands except decompression, ensure required directories exist.
case "${command}" in
  decompress)
    ;;
  *)
    mkdir -p "${ENTRIES_DIR}" "${LOG_DIR}"
    ;;
esac

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
    [ $# -ne 1 ] && { echo "Error: 'update' requires exactly 1 argument."; usage; }
    update_entry "$1"
    ;;
  rename)
    [ $# -ne 2 ] && { echo "Error: 'rename' requires exactly 2 arguments."; usage; }
    rename_entry "$1" "$2"
    ;;
  delete)
    [ $# -ne 1 ] && { echo "Error: 'delete' requires exactly 1 argument."; usage; }
    delete_entry "$1"
    ;;
  encrypt)
    [ $# -ne 1 ] && { echo "Error: 'encrypt' requires exactly 1 argument."; usage; }
    encrypt_entry "$1"
    ;;
  decrypt)
    [ $# -ne 1 ] && { echo "Error: 'decrypt' requires exactly 1 argument."; usage; }
    decrypt_entry "$1"
    ;;
  updateall)
    [ $# -ne 0 ] && { echo "Error: 'updateall' does not accept any arguments."; usage; }
    update_all_entries
    ;;
  search)
    [ $# -lt 1 ] && { echo "Error: 'search' requires a pattern."; usage; }
    search_entries "$@"
    ;;
  audit)
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
  compress)
    if [ "$#" -gt 1 ]; then
      echo "Error: 'compress' takes at most one argument." >&2
      usage
    fi
    compress_diary "$@"
    ;;
  decompress)
    if [ "$#" -ne 1 ]; then
      echo "Error: 'decompress' requires exactly one argument." >&2
      usage
    fi
    decompress_diary "$@"
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
