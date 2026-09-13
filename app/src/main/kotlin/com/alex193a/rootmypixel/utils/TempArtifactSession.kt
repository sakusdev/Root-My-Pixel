package com.alex193a.rootmypixel.utils

import android.content.Context
import java.security.SecureRandom

private val tempArtifactSessionLock = Any()

enum class TempArtifactSessionState {
    Preparing,
    Active,
    CleanupPending,
}

object TempArtifactWorkspaceContract {
    const val MARKER = "RMP_WORKSPACE_CONTRACT:v1"
    private val markerBytes = MARKER.encodeToByteArray()

    fun isSupported(binary: ByteArray): Boolean {
        if (binary.size < markerBytes.size) return false
        for (start in 0..binary.size - markerBytes.size) {
            var matches = true
            for (offset in markerBytes.indices) {
                if (binary[start + offset] != markerBytes[offset]) {
                    matches = false
                    break
                }
            }
            if (matches) return true
        }
        return false
    }
}

class TempArtifactPaths private constructor(
    val sessionId: String?,
    val workDir: String,
) {
    val exploitPayload: String = "$workDir/cve-2026-43499-app.so"
    val rootHelper: String = "$workDir/cve-2026-43499-root"
    val exploitLog: String = "$workDir/exploit.log"
    val suClient: String = "$workDir/su"
    val suSocket: String = "$workDir/temp_su.sock"
    val suDaemonLog: String = "$workDir/su_daemon.log"
    val kernelSuLoader: String = "$workDir/ksud-pixel"
    val paintLog: String = "$workDir/paint.log"
    val unrootLog: String = "$workDir/unroot.log"

    val isLegacy: Boolean
        get() = sessionId == null

    override fun equals(other: Any?): Boolean =
        other is TempArtifactPaths && sessionId == other.sessionId && workDir == other.workDir

    override fun hashCode(): Int = 31 * (sessionId?.hashCode() ?: 0) + workDir.hashCode()

    override fun toString(): String = "TempArtifactPaths(workDir=$workDir)"

    fun environment(): Map<String, String> = if (isLegacy) {
        emptyMap()
    } else {
        mapOf(WORK_DIR_ENV to workDir)
    }

    fun exportInto(script: String): String = if (isLegacy) {
        "unset $WORK_DIR_ENV\n$script"
    } else {
        "export $WORK_DIR_ENV=${shellQuote(workDir)}\n$script"
    }

    fun cveSuShellCommand(command: String): String = buildString {
        if (!isLegacy) {
            append(WORK_DIR_ENV)
            append('=')
            append(shellQuote(workDir))
            append(' ')
        }
        append(shellQuote(suClient))
        append(" -c ")
        append(shellQuote(command))
    }

    companion object {
        const val WORK_DIR_ENV = "RMP_WORK_DIR"
        const val WORK_DIR_CONFIG = "/apex/com.android.virt/bin/.rmp-work-dir"
        const val LEGACY_WORK_DIR = "/data/local/tmp"
        const val SESSION_WORK_DIR_PREFIX = "$LEGACY_WORK_DIR/"
        const val SESSION_ID_LENGTH = 32

        private val sessionIdRegex = Regex("[0-9a-f]{$SESSION_ID_LENGTH}")

        fun isValidSessionId(sessionId: String): Boolean =
            sessionIdRegex.matches(sessionId)

        fun fromSessionId(sessionId: String): TempArtifactPaths {
            require(isValidSessionId(sessionId)) { "Invalid temporary artifact session id" }
            return TempArtifactPaths(
                sessionId = sessionId,
                workDir = "$SESSION_WORK_DIR_PREFIX$sessionId",
            )
        }

        fun fromWorkDir(workDir: String): TempArtifactPaths? {
            if (workDir == LEGACY_WORK_DIR) return legacy()
            if (!workDir.startsWith(SESSION_WORK_DIR_PREFIX)) return null
            val sessionId = workDir.removePrefix(SESSION_WORK_DIR_PREFIX)
            return if (isValidSessionId(sessionId)) fromSessionId(sessionId) else null
        }

        fun legacy(): TempArtifactPaths = TempArtifactPaths(
            sessionId = null,
            workDir = LEGACY_WORK_DIR,
        )
    }
}

data class TempArtifactSession(
    val paths: TempArtifactPaths,
    val state: TempArtifactSessionState,
)

sealed interface TempArtifactSessionResolution {
    data object Missing : TempArtifactSessionResolution
    data class Invalid(val reason: String) : TempArtifactSessionResolution
    data class Found(val session: TempArtifactSession) : TempArtifactSessionResolution
}

internal data class StoredTempArtifactSession(
    val hasSession: Boolean,
    val schemaVersion: Int?,
    val sessionId: String?,
    val state: String?,
)

internal interface TempArtifactSessionPersistence {
    fun read(): StoredTempArtifactSession
    fun write(schemaVersion: Int, sessionId: String, state: String): Boolean
    fun clearIfMatches(sessionId: String): Boolean
}

private class SharedPreferencesTempArtifactSessionPersistence(
    context: Context,
) : TempArtifactSessionPersistence {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    override fun read(): StoredTempArtifactSession = StoredTempArtifactSession(
        hasSession = preferences.contains(KEY_SESSION_ID),
        schemaVersion = if (preferences.contains(KEY_SCHEMA_VERSION)) {
            preferences.getInt(KEY_SCHEMA_VERSION, 0)
        } else {
            null
        },
        sessionId = preferences.getString(KEY_SESSION_ID, null),
        state = preferences.getString(KEY_STATE, null),
    )

    override fun write(schemaVersion: Int, sessionId: String, state: String): Boolean =
        preferences.edit()
            .putInt(KEY_SCHEMA_VERSION, schemaVersion)
            .putString(KEY_SESSION_ID, sessionId)
            .putString(KEY_STATE, state)
            .commit()

    override fun clearIfMatches(sessionId: String): Boolean {
        if (preferences.getString(KEY_SESSION_ID, null) != sessionId) return false
        return preferences.edit()
            .remove(KEY_SCHEMA_VERSION)
            .remove(KEY_SESSION_ID)
            .remove(KEY_STATE)
            .commit()
    }

    companion object {
        private const val PREFERENCES_NAME = "temp_artifact_session"
        private const val KEY_SCHEMA_VERSION = "schema_version"
        private const val KEY_SESSION_ID = "session_id"
        private const val KEY_STATE = "state"
    }
}

class TempArtifactSessionStore internal constructor(
    private val persistence: TempArtifactSessionPersistence,
    private val generateSessionId: () -> String,
) {
    constructor(context: Context) : this(
        persistence = SharedPreferencesTempArtifactSessionPersistence(context),
        generateSessionId = ::secureSessionId,
    )

    fun resolve(): TempArtifactSessionResolution = synchronized(tempArtifactSessionLock) {
        val stored = persistence.read()
        if (!stored.hasSession) return@synchronized TempArtifactSessionResolution.Missing

        val sessionId = stored.sessionId
            ?: return@synchronized TempArtifactSessionResolution.Invalid("missing session id")
        if (!TempArtifactPaths.isValidSessionId(sessionId)) {
            return@synchronized TempArtifactSessionResolution.Invalid("invalid session id")
        }

        val state = stored.state
            ?.let { raw -> TempArtifactSessionState.entries.firstOrNull { it.name == raw } }
            ?: TempArtifactSessionState.CleanupPending
        TempArtifactSessionResolution.Found(
            TempArtifactSession(
                paths = TempArtifactPaths.fromSessionId(sessionId),
                state = if (stored.schemaVersion == SCHEMA_VERSION) {
                    state
                } else {
                    TempArtifactSessionState.CleanupPending
                },
            ),
        )
    }

    fun getOrCreate(): TempArtifactSession = synchronized(tempArtifactSessionLock) {
        when (val resolution = resolve()) {
            is TempArtifactSessionResolution.Found -> resolution.session
            is TempArtifactSessionResolution.Invalid ->
                throw IllegalStateException("Invalid temporary artifact session: ${resolution.reason}")
            TempArtifactSessionResolution.Missing -> {
                val sessionId = generateSessionId()
                check(TempArtifactPaths.isValidSessionId(sessionId)) {
                    "Temporary artifact session generator returned an invalid id"
                }
                check(
                    persistence.write(
                        schemaVersion = SCHEMA_VERSION,
                        sessionId = sessionId,
                        state = TempArtifactSessionState.Preparing.name,
                    ),
                ) { "Unable to persist temporary artifact session" }
                TempArtifactSession(
                    paths = TempArtifactPaths.fromSessionId(sessionId),
                    state = TempArtifactSessionState.Preparing,
                )
            }
        }
    }

    fun pathsForExistingTransport(): TempArtifactPaths? = synchronized(tempArtifactSessionLock) {
        when (val resolution = resolve()) {
            is TempArtifactSessionResolution.Found -> resolution.session.paths
            is TempArtifactSessionResolution.Invalid -> null
            TempArtifactSessionResolution.Missing -> TempArtifactPaths.legacy()
        }
    }

    fun adopt(paths: TempArtifactPaths): TempArtifactSession? =
        synchronized(tempArtifactSessionLock) {
            val sessionId = paths.sessionId ?: return@synchronized null
            when (val resolution = resolve()) {
                is TempArtifactSessionResolution.Found ->
                    resolution.session.takeIf { it.paths == paths }
                is TempArtifactSessionResolution.Invalid -> null
                TempArtifactSessionResolution.Missing -> {
                    if (!persistence.write(
                            SCHEMA_VERSION,
                            sessionId,
                            TempArtifactSessionState.CleanupPending.name,
                        )
                    ) return@synchronized null
                    TempArtifactSession(paths, TempArtifactSessionState.CleanupPending)
                }
            }
        }

    fun markState(sessionId: String, state: TempArtifactSessionState): Boolean =
        synchronized(tempArtifactSessionLock) {
            val current = resolve()
            if (current !is TempArtifactSessionResolution.Found ||
                current.session.paths.sessionId != sessionId
            ) return@synchronized false
            persistence.write(SCHEMA_VERSION, sessionId, state.name)
        }

    fun clearAfterCleanup(sessionId: String): Boolean = synchronized(tempArtifactSessionLock) {
        persistence.clearIfMatches(sessionId)
    }

    companion object {
        private const val SCHEMA_VERSION = 1
        private val secureRandom = SecureRandom()

        private fun secureSessionId(): String {
            val bytes = ByteArray(TempArtifactPaths.SESSION_ID_LENGTH / 2)
            secureRandom.nextBytes(bytes)
            return bytes.joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
        }
    }
}

private fun shellQuote(value: String): String =
    "'${value.replace("'", "'\"'\"'")}'"
