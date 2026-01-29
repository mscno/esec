# Format Go files
fmt:
    goimports -w .
    go fmt ./...

# Run linter
lint:
    golangci-lint run ./...

# Install git hooks
hooks:
    lefthook install

test:
    TEST_DATASTORE_PROJECT=esec-prod go test ./...

serve:
    ESEC_STORE=datastore ESEC_DATASTORE_DATABASE=esec-prod ESEC_DATASTORE_PROJECT=esec-prod go run ./cmd/esec-server/main.go

cover:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out

install:
    go install ./cmd/esec

build:
    go build -ldflags "-X 'main.VERSION=0.0.6'" -o esec ./cmd/esec
    ./esec --version

buf:
    buf generate server/proto --template server/proto/buf.go.yaml
