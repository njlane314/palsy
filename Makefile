.PHONY: run test dev clean

run:
	uvicorn palsy.api:app --host 0.0.0.0 --port 8080

test:
	pytest -q

dev:
	PALSY_STATE_DIR=./state uvicorn palsy.api:app --reload --host 127.0.0.1 --port 8080

clean:
	rm -rf state .pytest_cache **/__pycache__
