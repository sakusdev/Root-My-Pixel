#!/system/bin/sh
# Unroot and restore stock state for Root-My-Pixel.
# Structured UNROOT_* markers are consumed by the Android UI.

LEGACY_WORK_DIR="/data/local/tmp"
WORK_DIR="${RMP_WORK_DIR:-$LEGACY_WORK_DIR}"
if [ "$WORK_DIR" != "$LEGACY_WORK_DIR" ]; then
    case "$WORK_DIR" in
        /data/local/tmp/*) ;;
        *) echo "UNROOT_FAIL:workspace:invalid-path"; exit 1 ;;
    esac
    session_id=${WORK_DIR#/data/local/tmp/}
    if [ "${#session_id}" -ne 32 ]; then
        echo "UNROOT_FAIL:workspace:invalid-id"
        exit 1
    fi
    case "$session_id" in
        *[!0-9a-f]*) echo "UNROOT_FAIL:workspace:invalid-id"; exit 1 ;;
    esac
fi
export RMP_WORK_DIR="$WORK_DIR"

SU_PATH="$WORK_DIR/su"
SOCKET_PATH="$WORK_DIR/temp_su.sock"
LOG_FILE="$WORK_DIR/unroot.log"
echo "=== Unroot started at $(date) ===" > "$LOG_FILE" 2>/dev/null || true

log() {
    echo "[$(date +%T)] $*" | tee -a "$LOG_FILE" 2>/dev/null || echo "[$(date +%T)] $*"
}

exec_root() {
    local cmd="$1"
    local out
    local status

    if [ "$(id -u)" = "0" ]; then
        /system/bin/sh -c "$cmd"
        return $?
    fi

    if command -v su >/dev/null 2>&1; then
        out=$(su -c "$cmd" 2>&1)
        status=$?
        if [ $status -eq 0 ]; then
            [ -n "$out" ] && echo "$out"
            return 0
        fi
    fi

    if [ -x "$SU_PATH" ] && [ -S "$SOCKET_PATH" ]; then
        out=$(RMP_WORK_DIR="$WORK_DIR" "$SU_PATH" -c "$cmd" 2>&1)
        status=$?
        if [ $status -eq 0 ]; then
            [ -n "$out" ] && echo "$out"
            return 0
        fi
    fi

    echo "UNROOT_TRANSPORT_UNAVAILABLE"
    return 1
}

# This command returns zero after it starts as root. Cleanup failures use
# markers, preventing exec_root from repeating destructive work with another
# root provider merely because one cleanup step failed.
ROOT_UNROOT_COMMAND='
LEGACY_WORK_DIR="/data/local/tmp"
WORK_DIR="${RMP_WORK_DIR:-$LEGACY_WORK_DIR}"
failed=0
cleanup_step() {
    name="$1"
    shift
    "$@"
    status=$?
    if [ $status -eq 0 ]; then
        echo "UNROOT_OK:$name"
    else
        echo "UNROOT_FAIL:$name:$status"
        failed=1
    fi
}

echo "UNROOT_IDENTITY:uid=$(id -u):context=$(id -Z 2>/dev/null || true)"
cleanup_step data-adb /system/bin/sh -c '\''rm -rf /data/adb && [ ! -e /data/adb ]'\''
cleanup_step apex-mount /system/bin/sh -c '\''grep -q " /apex/com.android.virt/bin " /proc/mounts 2>/dev/null || exit 0; umount /apex/com.android.virt/bin'\''
cleanup_step selinux /system/bin/sh -c '\''[ "$(getenforce 2>/dev/null)" = "Enforcing" ] || { setenforce 1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; }'\''
cleanup_step cve-app rm -f "$WORK_DIR/cve-2026-43499-app.so" "$WORK_DIR/.cve-2026-43499-app.so.new"
cleanup_step cve-root rm -f "$WORK_DIR/cve-2026-43499-root" "$WORK_DIR/.cve-2026-43499-root.new"
cleanup_step ksud rm -f "$WORK_DIR/ksud-pixel"
cleanup_step exploit-logs rm -f "$WORK_DIR/exploit.log" "$WORK_DIR/su_daemon.log" "$WORK_DIR/paint.log" "$WORK_DIR/unroot.log"

if [ "$failed" -ne 0 ]; then
    echo "UNROOT_CLEANUP_PARTIAL"
    exit 0
fi

if [ "$WORK_DIR" != "$LEGACY_WORK_DIR" ]; then
    unexpected=0
    for path in "$WORK_DIR"/* "$WORK_DIR"/.[!.]* "$WORK_DIR"/..?*; do
        [ -e "$path" ] || [ -L "$path" ] || continue
        case "${path##*/}" in
            su|temp_su.sock|.su.new.*) ;;
            *) echo "UNROOT_FAIL:workspace:unexpected-file"; unexpected=1 ;;
        esac
    done
    if [ "$unexpected" -ne 0 ]; then
        echo "UNROOT_CLEANUP_PARTIAL"
        exit 0
    fi
fi

# Preserve the CVE transport whenever an earlier step fails, so the user can
# cancel and retry. On success this root shell survives deletion long enough
# to submit the reboot request atomically.
cleanup_step root-transport-files rm -f "$WORK_DIR"/.su.new.* "$WORK_DIR/temp_su.sock" "$WORK_DIR/su"
if [ "$failed" -ne 0 ]; then
    echo "UNROOT_CLEANUP_PARTIAL"
    exit 0
fi

if [ "$WORK_DIR" != "$LEGACY_WORK_DIR" ]; then
    cleanup_step workspace rmdir "$WORK_DIR"
    if [ "$failed" -ne 0 ]; then
        echo "UNROOT_CLEANUP_PARTIAL"
        exit 0
    fi
fi

sync
echo "UNROOT_CLEANUP_OK"
if svc power reboot || reboot; then
    echo "UNROOT_REBOOT_REQUESTED"
else
    status=$?
    echo "UNROOT_FAIL:reboot:$status"
fi
exit 0
'

log "Cleaning privileged root state and temporary files..."
if exec_root "$ROOT_UNROOT_COMMAND"; then
    log "Unroot command completed"
else
    log "Root execution unavailable; cleanup paused"
fi
