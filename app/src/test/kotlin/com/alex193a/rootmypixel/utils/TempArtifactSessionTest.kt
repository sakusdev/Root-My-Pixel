package com.alex193a.rootmypixel.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class TempArtifactSessionTest {
    @Test
    fun `workspace contract marker must be embedded in payload and helper`() {
        val supported = "prefix-${TempArtifactWorkspaceContract.MARKER}-suffix".encodeToByteArray()

        assertTrue(TempArtifactWorkspaceContract.isSupported(supported))
        assertFalse(TempArtifactWorkspaceContract.isSupported("old-payload".encodeToByteArray()))
    }

    @Test
    fun `session paths are derived from a strict lowercase hex id`() {
        val id = "0123456789abcdef0123456789abcdef"

        val paths = TempArtifactPaths.fromSessionId(id)

        assertEquals("/data/local/tmp/$id", paths.workDir)
        assertEquals("${paths.workDir}/temp_su.sock", paths.suSocket)
        assertEquals("${paths.workDir}/ksud-pixel", paths.kernelSuLoader)
        assertFalse(paths.isLegacy)
        assertNull(TempArtifactPaths.fromWorkDir("/data/local/tmp/${id.uppercase()}"))
        assertNull(TempArtifactPaths.fromWorkDir("/data/local/tmp/../../data"))
        assertNull(TempArtifactPaths.fromWorkDir("/data/local/tmp/rmp-session-$id"))
    }

    @Test
    fun `legacy paths are used only when no session was persisted`() {
        val persistence = FakePersistence()
        val store = TempArtifactSessionStore(persistence) { validId('a') }

        val paths = store.pathsForExistingTransport()

        assertTrue(paths?.isLegacy == true)
        assertEquals("/data/local/tmp/temp_su.sock", paths?.suSocket)
        assertTrue(paths?.environment()?.isEmpty() == true)
    }

    @Test
    fun `session environment exports only the validated work directory`() {
        val paths = TempArtifactPaths.fromSessionId(validId('a'))

        assertEquals(
            mapOf(TempArtifactPaths.WORK_DIR_ENV to paths.workDir),
            paths.environment(),
        )
        assertTrue(paths.exportInto("id -u").startsWith("export RMP_WORK_DIR='"))
    }

    @Test
    fun `persisted session is reused across store instances`() {
        val persistence = FakePersistence()
        val firstStore = TempArtifactSessionStore(persistence) { validId('b') }
        val first = firstStore.getOrCreate()
        val secondStore = TempArtifactSessionStore(persistence) { validId('c') }

        val second = secondStore.getOrCreate()

        assertEquals(first.paths, second.paths)
        assertEquals(1, persistence.writeCount)
    }

    @Test
    fun `concurrent store instances publish only one session`() {
        val persistence = FakePersistence()
        val generators = "abcdef0123456789"
        val stores = generators.map { character ->
            TempArtifactSessionStore(persistence) { validId(character) }
        }
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(4)
        try {
            val futures = stores.map { store ->
                executor.submit<TempArtifactSession> {
                    start.await()
                    store.getOrCreate()
                }
            }

            start.countDown()
            val paths = futures.map { it.get(5, TimeUnit.SECONDS).paths }.toSet()

            assertEquals(1, paths.size)
            assertEquals(1, persistence.writeCount)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `missing preferences can adopt the workspace reported by the daemon`() {
        val persistence = FakePersistence()
        val store = TempArtifactSessionStore(persistence) { validId('c') }
        val paths = TempArtifactPaths.fromSessionId(validId('b'))

        val adopted = store.adopt(paths)

        assertEquals(paths, adopted?.paths)
        assertEquals(TempArtifactSessionState.CleanupPending, adopted?.state)
        assertEquals(paths, store.pathsForExistingTransport())
    }

    @Test
    fun `invalid persisted id blocks transport and is never treated as legacy`() {
        val persistence = FakePersistence(
            stored = StoredTempArtifactSession(
                hasSession = true,
                schemaVersion = 1,
                sessionId = "../../data",
                state = TempArtifactSessionState.Active.name,
            ),
        )
        val store = TempArtifactSessionStore(persistence) { validId('d') }

        assertNull(store.pathsForExistingTransport())
        try {
            store.getOrCreate()
            fail("Expected invalid persisted state to block session creation")
        } catch (_: IllegalStateException) {
        }
        assertEquals(0, persistence.writeCount)
    }

    @Test
    fun `unknown schema and state preserve id but require cleanup`() {
        val id = validId('e')
        val persistence = FakePersistence(
            stored = StoredTempArtifactSession(
                hasSession = true,
                schemaVersion = 99,
                sessionId = id,
                state = "FutureState",
            ),
        )
        val store = TempArtifactSessionStore(persistence) { validId('f') }

        val resolution = store.resolve()

        assertTrue(resolution is TempArtifactSessionResolution.Found)
        val session = (resolution as TempArtifactSessionResolution.Found).session
        assertEquals(id, session.paths.sessionId)
        assertEquals(TempArtifactSessionState.CleanupPending, session.state)
    }

    @Test
    fun `cleanup clears only the matching session`() {
        val persistence = FakePersistence()
        val store = TempArtifactSessionStore(persistence) { validId('1') }
        val session = store.getOrCreate()

        assertFalse(store.clearAfterCleanup(validId('2')))
        assertTrue(store.resolve() is TempArtifactSessionResolution.Found)
        assertTrue(store.clearAfterCleanup(session.paths.sessionId!!))
        assertEquals(TempArtifactSessionResolution.Missing, store.resolve())
    }

    private fun validId(character: Char): String = character.toString().repeat(32)

    private class FakePersistence(
        var stored: StoredTempArtifactSession = StoredTempArtifactSession(
            hasSession = false,
            schemaVersion = null,
            sessionId = null,
            state = null,
        ),
    ) : TempArtifactSessionPersistence {
        var writeCount = 0

        override fun read(): StoredTempArtifactSession = stored

        override fun write(schemaVersion: Int, sessionId: String, state: String): Boolean {
            writeCount++
            stored = StoredTempArtifactSession(
                hasSession = true,
                schemaVersion = schemaVersion,
                sessionId = sessionId,
                state = state,
            )
            return true
        }

        override fun clearIfMatches(sessionId: String): Boolean {
            if (stored.sessionId != sessionId) return false
            stored = StoredTempArtifactSession(
                hasSession = false,
                schemaVersion = null,
                sessionId = null,
                state = null,
            )
            return true
        }
    }
}
