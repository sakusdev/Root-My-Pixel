package com.alex193a.rootmypixel.utils

import android.content.Context
import androidx.annotation.StringRes
import com.alex193a.rootmypixel.R

enum class UnrootIssue(
    val marker: String,
    @StringRes val labelRes: Int,
) {
    RootTransport("root-transport", R.string.unroot_issue_root_transport),
    KernelSuData("data-adb", R.string.unroot_issue_data_adb),
    ApexMount("apex-mount", R.string.unroot_issue_apex_mount),
    Selinux("selinux", R.string.unroot_issue_selinux),
    ExploitPayload("cve-app", R.string.unroot_issue_cve_app),
    RootHelper("cve-root", R.string.unroot_issue_cve_root),
    KernelSuLoader("ksud", R.string.unroot_issue_ksud),
    ExploitLogs("exploit-logs", R.string.unroot_issue_exploit_logs),
    Workspace("workspace", R.string.unroot_issue_workspace),
    RootTransportFiles("root-transport-files", R.string.unroot_issue_root_transport_files),
    Reboot("reboot", R.string.unroot_issue_reboot),
    Unknown("unknown", R.string.unroot_issue_unknown),
    ;

    companion object {
        fun fromMarker(marker: String): UnrootIssue =
            entries.firstOrNull { it.marker == marker } ?: Unknown

        val affectedByMissingTransport: List<UnrootIssue> = listOf(
            RootTransport,
            KernelSuData,
            ApexMount,
            Selinux,
            ExploitPayload,
            RootHelper,
            KernelSuLoader,
            ExploitLogs,
            Workspace,
            RootTransportFiles,
        )
    }
}

data class UnrootCommandOutcome(
    val cleanupComplete: Boolean,
    val rebootRequested: Boolean,
    val transportUnavailable: Boolean,
    val issues: List<UnrootIssue>,
    val hasStructuredOutput: Boolean,
) {
    fun failedItemsText(context: Context): String = issues
        .ifEmpty { listOf(UnrootIssue.Unknown) }
        .distinct()
        .joinToString(separator = "\n") { issue ->
            "• ${context.getString(issue.labelRes)}"
        }

    companion object {
        fun parse(output: String): UnrootCommandOutcome {
            val issues = output.lineSequence()
                .map(String::trim)
                .filter { it.startsWith(FAILURE_PREFIX) }
                .map { line ->
                    UnrootIssue.fromMarker(
                        line.removePrefix(FAILURE_PREFIX).substringBefore(':'),
                    )
                }
                .toList()

            val transportUnavailable = output.contains(TRANSPORT_UNAVAILABLE)
            val parsedIssues = buildList {
                addAll(issues)
                if (transportUnavailable) addAll(UnrootIssue.affectedByMissingTransport)
            }.distinct()

            return UnrootCommandOutcome(
                cleanupComplete = output.contains(CLEANUP_OK),
                rebootRequested = output.contains(REBOOT_REQUESTED),
                transportUnavailable = transportUnavailable,
                issues = parsedIssues,
                hasStructuredOutput = output.contains(MARKER_PREFIX),
            )
        }

        private const val MARKER_PREFIX = "UNROOT_"
        private const val FAILURE_PREFIX = "UNROOT_FAIL:"
        private const val TRANSPORT_UNAVAILABLE = "UNROOT_TRANSPORT_UNAVAILABLE"
        private const val CLEANUP_OK = "UNROOT_CLEANUP_OK"
        private const val REBOOT_REQUESTED = "UNROOT_REBOOT_REQUESTED"
    }
}
