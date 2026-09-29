.PHONY: run dry test lint check-links

run:
	python source/main.py

dry:
	python source/main.py --dry-run

test:
	pytest source/ -q

lint:
	ruff check source/

check-links:
	python source/check_links.py
