.PHONY: fmt test policy-test integration-test e2e-test sqlc compose-up compose-down

fmt:
	gofmt -w cmd internal

test:
	go test ./...

policy-test:
	docker run --rm -v "$(CURDIR)/policy:/policy:ro" openpolicyagent/opa:1.21.0-static test /policy

integration-test:
	go test -tags=integration ./internal/store -run TestPostgresFactsAndAudit -v

e2e-test:
	bash tests/e2e.sh

sqlc:
	docker run --rm -v "$(CURDIR):/src" -w /src sqlc/sqlc:1.31.1 generate

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
