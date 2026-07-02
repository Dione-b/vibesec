.PHONY: all build frontend backend clean dev dev-frontend dev-backend test lint install

all: build

dev:
	@echo "Iniciando backend (port 8080)..."
	@go run . serve &
	@sleep 2
	@echo "Iniciando frontend (port 5173)..."
	@cd frontend && npm run dev

frontend:
	cd frontend && npm run build

backend: frontend
	go build -o vibesec .

build: backend

dev-frontend:
	cd frontend && npm run dev

dev-backend:
	go run .

install:
	go mod download
	cd frontend && npm install

test:
	go test ./...

lint:
	cd frontend && npm run lint

clean:
	rm -rf frontend/dist frontend/node_modules vibesec
