sqlc:
	cd repo/db && sqlc generate

swagger:
	swag init --output api/swagger -g api/swagger/main.go

server: sqlc swagger
	CGO_ENABLED=0 go build -o server main.go

gen-python:
	cd report && go generate ./...
	rm -rf ./report/python/data/windows-amd64 \
		./report/python/data/linux-arm64 \
		./report/python/data/darwin-amd64 \
		./report/python/data/embed_darwin_amd64.go \
		./report/python/data/embed_linux_arm64.go \
		./report/python/data/embed_windows_amd64.go

run-server: server
	godotenv -f .env ./server \
		--port 8000 \
		--dev-logging \
		--cowrie-db-path ./var/cowrie.db
clean:
	rm -f server

# honeypot-specific
build-honeyfs:
	cd honeypot && \
	rm -rf real_honeyfs && \
	rm -rf fs.pickle && \
	bash build-honeyfs.sh

update-perms:
	mkdir -p ./var/cowrie/logs
	sudo chmod -R a+rw ./var/cowrie
