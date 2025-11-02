FROM golang:1.25 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -o /out/mpcium ./cmd/mpcium

FROM gcr.io/distroless/base-debian12:latest

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder /out/mpcium /app/mpcium

ENTRYPOINT ["/app/mpcium"]
