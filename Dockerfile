# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY main.go main.go
COPY api/ api/
COPY pkg/ pkg/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -o manager main.go

# Runtime stage
FROM alpine:3.19
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
