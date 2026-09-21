# teams-cli development commands

default: test

build:
    go build ./...

test:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- ./...

test-race:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- -race ./...

test-cover:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

lint:
    go tool -modfile=tools.go.mod golangci-lint run --timeout=5m

fmt:
    gofmt -w .

fmt-check:
    test -z "$(gofmt -l .)"

vet:
    go vet ./...

tidy:
    go mod tidy

tidy-tools:
    go mod tidy -modfile=tools.go.mod

ci: fmt-check vet test-race lint

clean:
    rm -rf bin coverage.out coverage.html

# Measure how much of the suite is load-bearing, by changing the code and
# seeing whether a test notices. A surviving mutant names something no test
# checks. This is deliberately not part of `ci`: it takes minutes, not seconds.
mutate *ARGS:
    go tool -modfile=tools.go.mod mutante run {{ARGS}}

# Boundary comparisons only, which is the fastest useful slice and where
# off-by-one bugs hide.
mutate-bounds:
    go tool -modfile=tools.go.mod mutante run --operators cond_boundary
