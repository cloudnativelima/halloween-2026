# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS derive

WORKDIR /src

COPY go.mod ./
COPY main.go ./
COPY decode.go ./

ARG TARGETOS
ARG TARGETARCH
RUN mkdir -p challenge-data
RUN --mount=type=secret,id=flag-seed,required=true \
    --mount=type=tmpfs,target=/src/challenge-data \
    /bin/sh <<'EOF'
set -eu

mkdir -p /out
go generate
CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/exorcise .
EOF

FROM scratch

COPY --from=derive /out/exorcise /exorcise

USER 65532:65532
ENTRYPOINT ["/exorcise"]
