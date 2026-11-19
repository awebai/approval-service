# Prepare the committed Python lock and Go cache before the runner goes offline.
JUNIT_XML ?= /tmp/awsign-service.xml

.PHONY: test collect

test:
	uv run --frozen --offline --no-sync python scripts/run_integration.py --junitxml "$(JUNIT_XML)"
	GOPROXY=off GOSUMDB=off go test ./...
	GOPROXY=off GOSUMDB=off go vet ./...

collect:
	uv run --frozen --offline --no-sync python scripts/run_integration.py --collect-only
