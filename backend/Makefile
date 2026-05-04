.PHONY: run install test docker

run:
	cd .. && PYTHONPATH=backend/src:. uvicorn app.main:app --port 8080 --reload

install:
	pip install -r requirements.txt
	pip install -r ../pipeline/requirements.txt

test:
	cd .. && PYTHONPATH=backend/src:. pytest backend/tests/ -v

docker:
	cd .. && docker build -f backend/docker/Dockerfile -t cnd-backend .
