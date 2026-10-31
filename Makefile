IMAGE = ghcr.io/cloudnativelima/kubectl-exorcise-2026
VERSION = v1
PLATFORMS = linux/amd64,linux/arm64
.PHONY: test build-local push overwrite-v1

test:
	go test ./...

build-local:
	@set -eu; \
	umask 077; \
	seed_file=$${TMPDIR:-/tmp}/kubectl-exorcise-seed.$$$$; \
	(set -C; : > "$$seed_file") 2>/dev/null || { echo "cannot create temporary seed file" >&2; exit 1; }; \
	trap 'rm -f "$$seed_file"' 0; \
	trap 'exit 1' 1 2 15; \
	openssl rand -hex 32 > "$$seed_file"; \
	docker build --no-cache --platform linux/amd64 \
		--secret id=flag-seed,src="$$seed_file" \
		-t $(IMAGE):$(VERSION) -f Containerfile .

push:
	@set -eu; \
	umask 077; \
	seed_file=$${TMPDIR:-/tmp}/kubectl-exorcise-seed.$$$$; \
	(set -C; : > "$$seed_file") 2>/dev/null || { echo "cannot create temporary seed file" >&2; exit 1; }; \
	trap 'rm -f "$$seed_file"' 0; \
	trap 'exit 1' 1 2 15; \
	openssl rand -hex 32 > "$$seed_file"; \
	docker build --no-cache --platform linux/amd64 \
		--secret id=flag-seed,src="$$seed_file" \
		-t $(IMAGE):$(VERSION) -f Containerfile .; \
	docker buildx build \
		--no-cache \
		--platform $(PLATFORMS) \
		--secret id=flag-seed,src="$$seed_file" \
		--tag $(IMAGE):$(VERSION) \
		--push \
		-f Containerfile .

overwrite-v1: override VERSION := v1
overwrite-v1: push
