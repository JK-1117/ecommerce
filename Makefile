sqlc:
	docker run --rm -v "$(shell cd)":/src -w /src sqlc/sqlc generate

goose-up:
	bin/goose -dir sql/schema postgres postgres://go_htmx:DevPassword@localhost:5432/go_htmx up

goose-down:
	bin/goose -dir sql/schema postgres postgres://go_htmx:DevPassword@localhost:5432/go_htmx down

tailwind:
	bin/tailwindcss -i main.css -o assets/css/style.css

server:
	go build -o tmp/main.exe cmd/main/main.go && tmp\\main.exe

build:
	go build -o cmd/main/main.exe cmd/main/main.go