.PHONY: run dry test lint

run:
	python source/main.py

dry:
	python source/main.py --dry-run

test:
	pytest source/ -q

lint:
	ruff check source/
