# Contributing to Occludra

Thanks for your interest in contributing to Occludra.

## Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run the tests (see below)
5. Commit and push
6. Open a Pull Request

## Development Setup

```bash
# Start services
docker compose up --build

# Run presidio tests
cd presidio
pip install -r requirements.txt
pytest tests/ -v
```

## Guidelines

- **Open an issue first** for significant changes — lets us discuss the approach before you invest time
- **Keep PRs focused** — one feature or fix per PR
- **Add tests** for new recognizers or DLP logic
- **No secrets** — never commit API keys, credentials, or `.env` files

## What We're Looking For

- New PII/secret recognizers (with tests and low false-positive rates)
- Prompt injection pattern improvements
- Documentation fixes
- Bug reports with reproduction steps
- Performance improvements

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
