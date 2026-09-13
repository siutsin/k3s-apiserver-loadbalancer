# Agent Instructions

## Rules

- Fix root causes. Never suppress warnings or hide errors.
- Keep files small with docstrings on new functions.
- Follow the Google Go Style Guide.
- Prefer values and small consumer-defined interfaces. Use pointers only to mutate.
- Design for eventual consistency. Minimise API load.
- No hardcoded error strings. No real network calls (fake client only).
- Unit tests: table-driven, black-box, under 10 seconds.

## Verify

Run these, all must pass:

`make lint-markdown-fix && make lint-go && make test && make test-e2e`
