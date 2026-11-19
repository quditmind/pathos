// The API token lives only in the IDE's PasswordSafe (the OS keychain, KeePass
// or the master-password store the user chose), keyed by the PATHOS URL so a
// token is never sent to a different server after the URL changes.
// Call from a background thread: the keychain can be slow.

package io.github.quditmind.pathos.settings

import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.Credentials
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import io.github.quditmind.pathos.api.validateBaseUrl

object TokenStore {
    /** Key of the token for a validated base URL. */
    fun serviceName(baseUrl: String): String = generateServiceName("PATHOS", "apiToken:${validateBaseUrl(baseUrl)}")

    private fun attributes(baseUrl: String) = CredentialAttributes(serviceName(baseUrl))

    fun get(baseUrl: String): String? = PasswordSafe.instance.getPassword(attributes(baseUrl))?.takeIf { it.isNotEmpty() }

    fun set(baseUrl: String, token: String) {
        PasswordSafe.instance.set(attributes(baseUrl), Credentials("api-token", token))
    }

    fun clear(baseUrl: String) {
        PasswordSafe.instance.set(attributes(baseUrl), null)
    }
}
