# Developer shortcuts. Every target runs its toolchain in a container.
.PHONY: help install up down logs test test-go test-web test-integration lint smoke build rbac-matrix

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

install: ## Create .env with generated secrets
	./deploy/scripts/install.sh

up: ## Build and start the stack, waiting for health
	docker compose up -d --build --wait

down: ## Stop the stack (keeps data)
	docker compose down

logs: ## Follow API logs
	docker compose logs -f api

build: ## Build images
	docker compose build

test: test-go test-web ## Unit tests (Go + frontend)

test-go:
	scripts/go.sh vet ./...
	scripts/go.sh test ./...

test-web:
	scripts/npm.sh ci --no-audit --no-fund
	scripts/npm.sh run typecheck
	scripts/npm.sh test

test-integration: ## Go integration tests against a throwaway PostgreSQL
	scripts/test-integration.sh

security: ## Security self-tests: gosec, govulncheck, npm audit, Trivy (images), ZAP baseline
	scripts/security-scan.sh

load-test: ## k6 load test against the running stack (see docs/OPERATIONS.md)
	scripts/load/run.sh

e2e: ## Browser end-to-end tests (Playwright) against the running stack
	scripts/e2e.sh

dast: ## Authenticated active ZAP API scan. DESTRUCTIVE: disposable stacks only
	scripts/dast.sh --destructive-ok

smoke: ## End-to-end test against the running stack
	python3 scripts/smoke-test.py

rbac-matrix: ## Print the RBAC matrix for docs/RBAC_MATRIX.md
	scripts/go.sh run ./cmd/pathosctl rbac-matrix
