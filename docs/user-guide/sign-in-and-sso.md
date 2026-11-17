---
title: Sign-in, MFA and single sign-on
section: user-guide
order: 2.5
version: "1.0"
updated: 2026-11-18
summary: How people sign in to PATHOS, two-factor authentication and recovery codes, and single sign-on with your company's SAML 2.0 or OpenID Connect identity provider.
---
# Sign-in, MFA and single sign-on

PATHOS signs people in through its bundled identity provider, Keycloak (realm `pathos`). Keycloak holds passwords (hashed), two-factor authenticators and recovery codes; PATHOS never sees them. PATHOS keeps the user record, roles and the audit log.

## Two-factor authentication (TOTP)

Administrators require two-factor authentication per user (**Users → user → Require MFA**) or for everyone (the MFA enforcement setting). The user sets up an authenticator app at the next sign-in.

## Recovery codes

Recovery codes let someone sign in when they lose their authenticator: on the code prompt they choose **Try another way** and enter one of their codes. Each code works once.

- **For yourself:** user menu → **Sign-in security** → **Set up recovery codes**, then sign out and in again. Keycloak shows 12 codes once; save them (for example in a password manager) and confirm.
- **For someone else (administrators):** **Users → user → Recovery codes → Require recovery codes** (or **Issue new codes** when they used or lost them). Old codes stop working when the new set is created.

Every request is recorded in the audit log (`user.recovery_codes`, `user.require_recovery_codes`).

Recovery codes are switched on by the one-time `keycloak-setup` job of the Docker Compose stack (it allows the recovery code form as an alternative to the authenticator in the sign-in flow). It runs on every `docker compose up` and changes nothing when the setting is already in place.

## Single sign-on with your identity provider

Keycloak brokers sign-in to your company identity provider over **SAML 2.0** or **OpenID Connect** (Microsoft Entra ID, Okta, Google Workspace, Ping, ADFS, another Keycloak…). The PATHOS sign-in page then shows a button for it. PATHOS itself does not change: it receives the same signed identity from Keycloak.

### What PATHOS does with a new SSO user

- The first sign-in creates the PATHOS user **with no roles**: they see nothing until an administrator grants a role (**Users**). To give roles in advance, **invite** the user with the same e-mail address: the invitation is linked on first sign-in.
- An invitation is linked only when the e-mail address is **verified**. For SSO users that is the case only when the identity provider is set to **Trust email**. Turn that on only for an identity provider whose e-mail addresses you control (your own company directory), otherwise anyone who can choose their e-mail address in that provider could take over an invitation.
- A Keycloak account that already exists with the same e-mail address is not taken over: Keycloak asks the person to confirm by signing in to the existing account first (the default *first broker login* flow).
- Deactivating a user in PATHOS blocks their sign-in even when the identity provider still accepts them.

### Add an OpenID Connect provider (for example Microsoft Entra ID)

1. In your provider, register an application (Entra ID: **App registrations → New registration**, platform **Web**). Redirect URI: `<PATHOS URL>/auth/realms/pathos/broker/<alias>/endpoint`, where `<alias>` is a short name you choose, such as `entra`. Create a client secret.
2. Keycloak administration (`<PATHOS URL>/auth/admin/`, realm **pathos**) → **Identity providers → OpenID Connect v1.0**.
3. **Alias**: the same `<alias>`. **Display name**: the button label, e.g. *Company account*. **Discovery endpoint**: your provider's `/.well-known/openid-configuration` URL (Entra ID: `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`). **Client ID** and **Client secret** from step 1. **Client authentication**: *Client secret sent as post*.
4. Under **Advanced**: **Validate signatures** on (with the JWKS URL from discovery), **PKCE** on (S256), **Scopes** `openid email profile`.
5. **Trust Email**: see above. Save.

### Add a SAML 2.0 provider (for example Okta or ADFS)

1. Keycloak administration → realm **pathos** → **Identity providers → SAML v2.0**. Choose an **Alias** (e.g. `okta`). Import your provider's metadata (**SAML entity descriptor** URL or file), or enter **Single Sign-On service URL**, **Identity provider entity ID** and the signing certificate.
2. In your provider, create a SAML application with:
   - **Entity ID / audience**: `<PATHOS URL>/auth/realms/pathos`
   - **Assertion consumer service (ACS) URL**: `<PATHOS URL>/auth/realms/pathos/broker/<alias>/endpoint` (HTTP-POST)
   - **Name ID**: e-mail address; attributes `email`, `firstName`, `lastName`.
   Keycloak's SP metadata is at `<PATHOS URL>/auth/realms/pathos/broker/<alias>/endpoint/descriptor`.
3. Back in Keycloak: **Principal type** *Attribute name*, **Principal attribute** `email`; **HTTP-POST binding response** on; **Validate signatures** and **Want assertions signed** on. Add **Mappers** of type *Attribute Importer* for `email`, `firstName` and `lastName`.
4. **Trust Email**: see above. Save.

### Make SSO the only way in (optional)

To send everyone straight to your provider, set it as the default in **Authentication → browser flow → Identity Provider Redirector → settings** (default identity provider = your alias). Keep at least one local administrator who can sign in without SSO (with **Try another way** or by opening `<PATHOS URL>/auth/realms/pathos/account`), so you can recover if the provider is unavailable.

### Test it

`scripts/test-sso-brokering.py` checks the whole chain on a running stack. It creates a temporary realm that plays an external OIDC and SAML identity provider, registers both as described above, signs in through each like a browser, checks that PATHOS creates the user without any access, and removes everything it created.

### Troubleshooting

| Symptom | Cause |
|---|---|
| Keycloak error *invalid_signature* after the provider's sign-in | Wrong signing certificate in the SAML provider (use the provider's current signing key) |
| *Invalid redirect URI* at the provider | The redirect / ACS URL must be exactly `<PATHOS URL>/auth/realms/pathos/broker/<alias>/endpoint` |
| PATHOS shows *sign-in failed* after Keycloak | The provider sent no e-mail address: map the `email` claim or attribute |
| User signed in but sees nothing | Expected: grant a role in **Users**, or invite the e-mail address beforehand with **Trust email** on |
