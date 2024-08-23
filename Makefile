build: download
	go build -o bookly.exe cmd/stend/main.go

download:
	go mod download && go mod verify

run: download
	go run cmd/stend/main.go

run-docker:
	docker compose up -d

test: download
	go test ./...

cover: download
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

all: download test cover build run-docker