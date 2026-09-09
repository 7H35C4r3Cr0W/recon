# Nabu Agent — developer shortcuts. `make help` lists targets.
.PHONY: help up down migrate seed test lint typecheck fe-dev build logs
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'
up: ## Bring up the full stack (api, worker, frontend, postgres, redis) + run migrations
	docker compose up -d --build
down: ## Stop the stack
	docker compose down
migrate: ## Apply DB migrations + seed the first admin (one-shot)
	docker compose run --rm migrate
seed: ## Seed the first admin only
	docker compose run --rm api python -m nabu_agent.bootstrap
test: ## Run unit tests (engine mocked)
	uv run pytest -q -m "not invariant"
invariants: ## Run the policy-invariant gate (must pass)
	uv run pytest -q -m invariant
lint: ## ruff
	uv run ruff check
typecheck: ## mypy
	uv run mypy nabu_agent
fe-dev: ## Run the Vite dev server (proxies /api + /ws to the api container)
	cd frontend && npm install && npm run dev
build: ## Build the api/worker + frontend images
	docker compose build
logs: ## Tail all service logs
	docker compose logs -f
