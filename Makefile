.PHONY: up down logs fmt

up:
	docker compose up --build

down:
	docker compose down -v

logs:
	docker compose logs -f --tail=200

fmt:
	@echo "add formatters later (ruff/black, etc.)"
