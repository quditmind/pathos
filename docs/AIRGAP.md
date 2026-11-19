# Air-gapped installation

PATHOS runs without internet access. Nothing in it needs an external service: authentication (Keycloak), the database, scanners and the optional AI (a local model with Ollama) all run on your hosts. What changes offline is how **vulnerability data** arrives: you bring it in as a signed-off bundle instead of letting the scanners download it.

## 1. On a connected machine

1. **Images.** Pull or build the release and save every image the stack uses:

   ```
   docker compose pull            # or: docker compose build
   docker save $(docker compose config --images | sort -u) -o pathos-images.tar
   ```

   The list includes PATHOS (api, jobs, scheduler, proxy, worker-core), PostgreSQL, Valkey, Keycloak, the Squid egress proxy and, if you use them, Mailpit and Ollama. Images are pinned by digest in `docker-compose.yml`, so the same versions are loaded on the other side.

2. **Vulnerability data.** Create an offline bundle:

   ```
   scripts/offline-bundle.sh create pathos-offline-$(date +%F).tar
   ```

   It contains the Trivy database (and its Java database), the Grype database, the OSV databases for npm, PyPI, Go, Maven, crates.io, NuGet, RubyGems, Packagist, Pub and Hex (for OSV-Scanner), and the EPSS and CISA KEV feed files, with a SHA-256 manifest. It is about 6–7 GB and takes a few minutes; `PATHOS_OSV_ECOSYSTEMS="npm PyPI"` limits the OSV part. The databases are downloaded with the tools of the PATHOS worker image itself, so they match the scanner versions.

3. **AI model (optional).** `docker compose exec ollama ollama pull qwen2.5-coder:7b`, then copy the `ollama_models` volume (for example `docker run --rm -v pathos_ollama_models:/m -v "$PWD":/o alpine tar -C /m -cf /o/models.tar .`).

4. Copy the repository checkout (or the release files), `pathos-images.tar`, the bundle and the model archive to the air-gapped side with your approved transfer process.

## 2. On the air-gapped host

1. `docker load -i pathos-images.tar`.
2. Run `deploy/scripts/install.sh` as usual, then add to `.env`:

   ```
   PATHOS_OFFLINE=true
   ```

   With it, the worker uses only local vulnerability databases (Trivy and Grype never update, OSV-Scanner uses its offline databases), and the API never downloads intelligence feeds (they are imported from files; the Risk & intelligence page says so).
3. Keep the egress allow-list (`deploy/egress/allowlist.txt`) empty or limited to internal hosts (your Git server, registry, Jira). The worker has no other way out.
4. `docker compose up -d --wait`.
5. Import the bundle:

   ```
   scripts/offline-bundle.sh import pathos-offline-2026-11-18.tar
   scripts/offline-bundle.sh status
   ```

   `import` refuses bundles with links or unsafe paths, verifies every checksum, and replaces the databases in the scanner cache volume. To import the EPSS and KEV feeds in the same step, create a REST API token with `api:write` (an administrator's, user menu → API tokens) and set `PATHOS_API_TOKEN` (and `PATHOS_CURL_INSECURE=1` with the default self-signed certificate); otherwise import `offline-feeds/epss.csv.gz` and `offline-feeds/kev.json` in **Risk & intelligence → Import file**.
6. AI (optional): restore the model archive into the `ollama_models` volume and select the self-hosted provider in **AI settings**.

## 3. Keep it current

Vulnerability data is only as fresh as the last bundle. Create and import a bundle **at least weekly** (daily for internet-facing systems). `scripts/offline-bundle.sh status` shows the dates; Grype's database age check is disabled offline so an older bundle still works, so watch those dates.

## What is different offline

| Feature | Offline |
|---|---|
| Repository scanning (Gitleaks, Opengrep, Trivy, Grype, OSV-Scanner, Syft, Checkov, zizmor, actionlint) | Works, with bundle data |
| Container image targets | Work against an internal registry |
| DAST (Nuclei) | Works against internal applications (templates are in the image) |
| EPSS, KEV, OSV intelligence | File import (bundle) |
| deps.dev package health | Not available (it is an online service) |
| End-of-life data (endoflife.date) | File import: download `https://endoflife.date/api/v1/products/full` on a connected machine and import it in **Risk & intelligence** |
| Declared endpoint verification | Disabled (it contacts the endpoints) |
| Signature verification (cosign) | Key-based only, without the transparency log; keyless verification is reported as skipped |
| SCM integrations | Internal servers (GitHub Enterprise Server, GitLab self-managed, Azure DevOps Server) |
| Webhooks, Jira, ServiceNow | Internal endpoints (allow internal addresses on each) |
| AI | Self-hosted model only |
| Malware scanning (ClamAV, optional: uploads and the `clamav` repository scanner) | The offline bundle does not include ClamAV signatures; `freshclam` cannot update them without internet access |
| Sign-in, MFA, recovery codes, SSO | Work (SSO with an internal identity provider) |

## Verify

Scan a repository whose dependencies have known vulnerabilities and check that Trivy, Grype and OSV-Scanner each report them. A scanner whose database is missing fails with "offline mode: vulnerability database missing; import an offline bundle".
