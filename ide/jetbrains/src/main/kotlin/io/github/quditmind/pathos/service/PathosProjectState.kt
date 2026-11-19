// Per-project choices, stored in the workspace file (.idea/workspace.xml),
// which is not shared through version control: the selected PATHOS
// repository and the tree grouping.

package io.github.quditmind.pathos.service

import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.StoragePathMacros
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
@State(name = "PathosProject", storages = [Storage(StoragePathMacros.WORKSPACE_FILE)])
class PathosProjectState : PersistentStateComponent<PathosProjectState.State> {
    class State {
        /** PATHOS base URL the repository belongs to. */
        var baseUrl: String = ""
        var repositoryId: String = ""
        var repositoryFullName: String = ""

        /** Local directory (the git checkout) finding paths are relative to. */
        var rootPath: String = ""

        /** "severity" or "file". */
        var grouping: String = "severity"
    }

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    companion object {
        fun getInstance(project: Project): PathosProjectState = project.getService(PathosProjectState::class.java)
    }
}
