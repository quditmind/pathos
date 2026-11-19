package io.github.quditmind.pathos.service

import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity

/** Loads the findings when a project opens. */
class PathosStartupActivity : ProjectActivity {
    override suspend fun execute(project: Project) {
        PathosProjectService.getInstance(project).start()
    }
}
