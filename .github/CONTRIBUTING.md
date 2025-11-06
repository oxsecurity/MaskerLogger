# Contributing to MaskerLogger

Thank you for your interest in contributing to MaskerLogger! We welcome contributions from the community.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/MaskerLogger.git`
3. Create a feature branch: `git checkout -b feature-branch`
4. Set up your development environment (see below)

## Development Setup

MaskerLogger uses Poetry for dependency management. We recommend using UV for faster installations.

```bash
# Install dependencies
poetry install

# Activate virtual environment
poetry shell

# Or use uv (if available)
uv pip install -e ".[dev]"
```

### Pre-commit Hooks

We use pre-commit to ensure code quality before commits. Install the hooks:

```bash
# Install pre-commit hooks
poetry run pre-commit install

# Run hooks manually on all files
poetry run pre-commit run --all-files
```

The pre-commit hooks will automatically:
- Run Ruff linting and formatting
- Run mypy type checking
- Check for trailing whitespace
- Validate YAML and TOML files
- Detect potential issues (large files, merge conflicts, private keys)
- Verify Poetry configuration

## Code Style

We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting, and [mypy](https://mypy.readthedocs.io/) for type checking:

```bash
# Run linting
poetry run ruff check .

# Run formatting
poetry run ruff format .

# Run type checking
poetry run mypy maskerlogger/
```

### Python Style Guidelines

- Use type annotations for all functions and classes
- Add docstrings to all functions and classes (PEP 257 convention)
- Files should be concise (typically < 250 lines)
- Functions should do one thing and be short
- Use meaningful names that reveal intent
- Follow the "return early" pattern instead of nested if/else
- Don't repeat yourself - abstract and reuse code

## Testing

We use pytest for testing. All tests must pass before submitting a PR.

```bash
# Run tests
poetry run pytest tests/

# Run tests with coverage
poetry run pytest tests/ --cov=maskerlogger --cov-report=html
```

### Test Guidelines

- Use pytest (NOT unittest module)
- Add type annotations to test functions
- Test names should be self-explanatory (no docstrings needed)
- All tests should be in the `./tests` directory
- Create `__init__.py` files as needed

## Submitting Changes

1. Ensure all tests pass
2. Pre-commit hooks will automatically run on commit (or run manually: `poetry run pre-commit run --all-files`)
3. If you haven't set up pre-commit, ensure code passes linting: `poetry run ruff check .`
4. Format your code: `poetry run ruff format .`
5. Commit your changes with a descriptive message and push
6. Open a Pull Request

## Pull Request Process

1. Fill out the PR template completely
2. Link any related issues
3. Ensure all CI checks pass
4. Wait for review from maintainers
5. Address any feedback
6. Once approved, a maintainer will merge your PR

## Questions?

If you have questions, feel free to:
- Open an issue for discussion
- Check existing issues and discussions
- Reach out to the maintainers

Thank you for contributing! 🎉
