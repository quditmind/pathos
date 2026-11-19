// Reading git remotes from a checkout's .git/config. Pure: java.nio only.

package io.github.quditmind.pathos.core

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

object GitConfig {
    private val GITDIR_RE = Regex("^gitdir:\\s*(.+)$", RegexOption.MULTILINE)
    private const val MAX_CONFIG_BYTES = 1L shl 20

    /** True when [dir] contains a .git directory or a .git file (worktree, submodule). */
    fun isGitRoot(dir: Path): Boolean = Files.exists(dir.resolve(".git"))

    /** Remote URLs of the repository checked out in [root], or an empty list. */
    fun remotesOf(root: Path): List<String> = try {
        val config = gitDir(root)?.resolve("config")
        if (config == null || !Files.isRegularFile(config) || Files.size(config) > MAX_CONFIG_BYTES) {
            emptyList()
        } else {
            parseGitConfigRemotes(String(Files.readAllBytes(config), StandardCharsets.UTF_8))
        }
    } catch (_: IOException) {
        emptyList()
    } catch (_: SecurityException) {
        emptyList()
    }

    /** The git directory of [root]: .git, or the common directory of a worktree. */
    private fun gitDir(root: Path): Path? {
        val dotGit = root.resolve(".git")
        if (Files.isDirectory(dotGit)) return dotGit
        if (!Files.isRegularFile(dotGit)) return null
        // Worktree or submodule: ".git" is a file "gitdir: <path>".
        val m = GITDIR_RE.find(String(Files.readAllBytes(dotGit), StandardCharsets.UTF_8)) ?: return null
        var dir = root.resolve(m.groupValues[1].trim()).normalize()
        val commonFile = dir.resolve("commondir")
        if (Files.isRegularFile(commonFile)) {
            val common = String(Files.readAllBytes(commonFile), StandardCharsets.UTF_8).trim()
            if (common.isNotEmpty()) dir = dir.resolve(common).normalize()
        }
        return dir
    }
}
