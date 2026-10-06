.PHONY: dev test lint

dev:
	flask --app app run --port 8000

test:
	pytest -q

lint:
	ruff check app
