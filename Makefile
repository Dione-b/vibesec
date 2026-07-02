.PHONY: all build frontend backend clean dev dev-stop dev-frontend dev-backend test lint install

all: build

dev:
	@chmod +x scripts/dev.sh
	@./scripts/dev.sh

dev-stop:
	@chmod +x scripts/dev-stop.sh
	@./scripts/dev-stop.sh

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
