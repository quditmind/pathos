// "Select repository": detected repositories first, then every repository
// the account can see; with several git checkouts, also the checkout.

package io.github.quditmind.pathos.ui

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.popup.JBPopupFactory
import com.intellij.notification.NotificationType
import io.github.quditmind.pathos.api.PathosApiException
import io.github.quditmind.pathos.api.Repository
import io.github.quditmind.pathos.service.GitCheckout
import io.github.quditmind.pathos.service.PathosProjectService
import io.github.quditmind.pathos.service.RepositoryCandidates
import java.nio.file.Path

object RepositoryChooser {
    private data class Item(val repo: Repository, val checkout: GitCheckout?, val detected: Boolean) {
        val label: String
            get() {
                val extra = listOfNotNull(repo.displayName?.takeIf { it.isNotEmpty() }, repo.repositoryKey?.takeIf { it.isNotEmpty() })
                val suffix = if (extra.isEmpty()) "" else "  ·  " + extra.joinToString(" · ")
                return (if (detected) "Detected: " else "") + repo.fullName + suffix
            }
    }

    fun choose(project: Project) {
        val service = PathosProjectService.getInstance(project)
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "PATHOS: loading repositories", true) {
            override fun run(indicator: ProgressIndicator) {
                val client = service.client(true) ?: return
                val candidates = try {
                    service.loadCandidates(client)
                } catch (e: PathosApiException) {
                    service.reportError(e, "Loading repositories", true)
                    return
                }
                ApplicationManager.getApplication().invokeLater({ show(project, candidates) }, project.disposed)
            }
        })
    }

    private fun show(project: Project, c: RepositoryCandidates) {
        val service = PathosProjectService.getInstance(project)
        val matched = c.matches.map { it.first.id }.toSet()
        val items = c.matches.map { Item(it.first, it.second, true) } +
            c.repositories.filter { it.id !in matched }.map { Item(it, null, false) }
        if (items.isEmpty()) {
            service.notify("Your PATHOS account cannot see any repositories.", NotificationType.INFORMATION)
            return
        }
        JBPopupFactory.getInstance().createPopupChooserBuilder(items)
            .setTitle("PATHOS: Select Repository")
            .setRenderer(plainTextRenderer<Item> { it.label })
            .setNamerForFiltering { it.repo.fullName + " " + (it.repo.displayName ?: "") + " " + (it.repo.repositoryKey ?: "") }
            .setVisibleRowCount(15)
            .setItemChosenCallback { item ->
                if (item.checkout != null || c.checkouts.size <= 1) {
                    select(project, c, item.repo, item.checkout?.root ?: c.checkouts.firstOrNull()?.root)
                } else {
                    chooseCheckout(project, c, item.repo)
                }
            }
            .createPopup()
            .showCenteredInCurrentWindow(project)
    }

    private fun chooseCheckout(project: Project, c: RepositoryCandidates, repo: Repository) {
        JBPopupFactory.getInstance().createPopupChooserBuilder(c.checkouts.map { it.root })
            .setTitle("Checkout That Contains ${repo.fullName}")
            .setRenderer(plainTextRenderer<Path> { it.toString() })
            .setItemChosenCallback { root -> select(project, c, repo, root) }
            .createPopup()
            .showCenteredInCurrentWindow(project)
    }

    private fun select(project: Project, c: RepositoryCandidates, repo: Repository, root: Path?) {
        val service = PathosProjectService.getInstance(project)
        service.rememberRepository(c.client.baseUrl, repo, root)
        service.refresh(true)
    }
}
