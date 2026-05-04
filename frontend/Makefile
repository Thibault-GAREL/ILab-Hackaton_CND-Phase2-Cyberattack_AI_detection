.PHONY: help install dev build preview test e2e lint format type-check docker-build docker-run docker-up docker-down docker-logs docker-restart docker-reload clean streamlit

help:
	@echo "DIRISI 2025 Frontend Streamlit - Available commands:"
	@echo ""
	@echo "📦 Streamlit (New):"
	@echo "  make streamlit    Start Streamlit app"
	@echo "  make streamlit-docker  Build and run with Docker"
	@echo ""
	@echo "📦 Development (Legacy React):"
	@echo "  make install      Install dependencies"
	@echo "  make dev          Start development server"
	@echo "  make build        Build for production"
	@echo "  make preview      Preview production build"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test         Run unit tests"
	@echo "  make e2e          Run E2E tests"
	@echo ""
	@echo "🔍 Quality:"
	@echo "  make lint         Lint code"
	@echo "  make format       Format code"
	@echo "  make type-check   Type check"
	@echo ""
	@echo "🐳 Docker (Full Stack):"
	@echo "  make docker           Launch frontend + backend (Ctrl+C to stop)"
	@echo "  make docker-reload    Stop, rebuild and restart with logs"
	@echo "  make docker-up        Start frontend + backend with Docker Compose"
	@echo "  make docker-down      Stop all Docker services"
	@echo "  make docker-logs      Show Docker logs"
	@echo "  make docker-restart   Restart Docker services"
	@echo "  make docker-build     Build Docker images"
	@echo "  make docker-clean     Remove all Docker resources"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean        Clean build artifacts"

streamlit:
	@echo "Starting Streamlit app..."
	streamlit run streamlit_app.py --server.port=3000 --client.showSidebarNavigation false

streamlit-docker:
	@echo "Building and running Streamlit with Docker..."
	docker build -t dirisi-frontend-streamlit:latest -f Dockerfile.streamlit .
	docker run --rm -p 3000:3000 --name dirisi-frontend dirisi-frontend-streamlit:latest

install:
	npm ci

dev:
	npm run dev

build:
	npm run build

preview:
	npm run preview

test:
	npm run test

e2e:
	npm run test:e2e

lint:
	npm run lint

format:
	npm run format

type-check:
	npm run type-check

# Docker Compose commands (Full Stack)
docker:
	@echo "🚀 Starting Frontend + Backend with Docker Compose..."
	@echo "   Press Ctrl+C to stop"
	docker compose -f docker/docker-compose.yml up --build

docker-up:
	@echo "🚀 Starting Frontend + Backend with Docker Compose..."
	docker compose -f docker/docker-compose.yml up --build

docker-down:
	@echo "🛑 Stopping Docker services..."
	docker compose -f docker/docker-compose.yml down

docker-logs:
	@echo "📋 Showing Docker logs..."
	docker compose -f docker/docker-compose.yml logs -f

docker-restart:
	@echo "🔄 Restarting Docker services..."
	docker compose -f docker/docker-compose.yml restart

docker-reload:
	@echo "🔄 Stopping and removing Docker services..."
	docker compose -f docker/docker-compose.yml down --remove-orphans
	@echo "🔨 Rebuilding and starting with logs..."
	docker compose -f docker/docker-compose.yml up --build

docker-build:
	@echo "🔨 Building Docker images..."
	docker compose -f docker/docker-compose.yml build

docker-clean:
	@echo "🧹 Cleaning Docker resources..."
	docker compose -f docker/docker-compose.yml down -v --rmi all

# Legacy single container commands
docker-build-frontend:
	docker build -t dirisi25-frontend:latest -f docker/Dockerfile .

docker-run-frontend:
	docker run --rm -p 3000:3000 --name dirisi25-frontend dirisi25-frontend:latest

clean:
	rm -rf dist node_modules coverage test-results playwright-report
