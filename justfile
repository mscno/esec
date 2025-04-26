test:
    TEST_DATASTORE_PROJECT=esec-prod go test ./...

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