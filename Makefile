build:
	@go build -o bin/foistbank

run: build
	@./bin/foistbank

test: 
	@go test -v ./...