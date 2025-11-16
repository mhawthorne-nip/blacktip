# Packaging Guide for Blacktip

This project uses modern Python packaging with `pyproject.toml` (PEP 517/518).

## Installation

### For Users

```bash
# Install from source
pip install .

# Install with YAML support
pip install .[yaml]

# Install with all optional dependencies
pip install .[all]
```

### For Developers

```bash
# Install in development mode (editable)
pip install -e .

# Install with development dependencies
pip install -e .[dev]

# Or use requirements files
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Configuration Files

### Primary Configuration: `pyproject.toml`
This is the single source of truth for:
- **Project metadata** (name, version, description, authors)
- **Dependencies** (runtime and optional)
- **Entry points** (CLI commands)
- **Build system** configuration
- **Tool configurations** (pytest, coverage)

### Backward Compatibility: `setup.py`
A minimal shim exists for backward compatibility with older tools. All actual configuration is in `pyproject.toml`.

### Requirements Files
- **`requirements.txt`** - Production dependencies (synced with pyproject.toml)
- **`requirements-dev.txt`** - Development and testing dependencies

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=blacktip --cov-report=html

# Run specific test file
pytest tests/test_validation.py

# Run specific test
pytest tests/test_validation.py::TestIPValidation::test_valid_ip_addresses
```

## Building Distributions

```bash
# Install build tools
pip install build

# Build source distribution and wheel
python -m build

# This creates:
# - dist/blacktip-1.0.0.tar.gz (source distribution)
# - dist/blacktip-1.0.0-py3-none-any.whl (wheel)
```

## Publishing to PyPI

```bash
# Install twine
pip install twine

# Check the distribution
twine check dist/*

# Upload to TestPyPI (for testing)
twine upload --repository testpypi dist/*

# Upload to PyPI (production)
twine upload dist/*
```

## Dependency Management

### Adding New Dependencies

Edit `pyproject.toml`:

```toml
[project]
dependencies = [
    "new-package>=1.0.0,<2.0.0",  # Add here for runtime deps
]

[project.optional-dependencies]
feature = [
    "optional-package>=1.0.0",    # Add here for optional deps
]
```

Then update `requirements.txt`:
```bash
pip install -e .
pip freeze | grep "new-package" >> requirements.txt
```

### Updating Dependencies

```bash
# Update all dependencies to latest compatible versions
pip install --upgrade -e .[all]

# Regenerate requirements files
pip freeze > requirements-frozen.txt  # Full freeze with all deps
```

## Version Bumping

1. Edit version in `pyproject.toml`:
   ```toml
   version = "1.1.0"
   ```

2. Also update in `src/blacktip/__init__.py`:
   ```python
   __version__ = "1.1.0"
   ```

3. Update CHANGELOG.md with changes

4. Commit and tag:
   ```bash
   git commit -am "Bump version to 1.1.0"
   git tag -a v1.1.0 -m "Version 1.1.0"
   git push && git push --tags
   ```

## Project Structure

```
blacktip/
├── pyproject.toml          # Main configuration (PEP 517/518)
├── setup.py                # Minimal backward compatibility shim
├── requirements.txt        # Production dependencies
├── requirements-dev.txt    # Development dependencies
├── README.md              # Project documentation
├── CHANGELOG.md           # Version history
├── LICENSE                # BSD-2-Clause license
├── src/
│   └── blacktip/          # Source code
│       ├── __init__.py    # Package initialization
│       ├── cli/           # Command-line interface
│       ├── utils/         # Utility modules
│       └── exceptions/    # Custom exceptions
└── tests/                 # Test suite
    ├── __init__.py
    └── test_*.py          # Test modules
```

## Tool Configurations in pyproject.toml

### Pytest
Configuration in `[tool.pytest.ini_options]`:
- Test discovery paths
- Test markers (unit, integration, slow)
- Default options (verbosity, warnings, timeout)

### Coverage
Configuration in `[tool.coverage.*]`:
- Source paths to measure
- Files to omit from coverage
- Lines to exclude from reports

## Migration from Old Setup

If you had a custom `setup.py`:

1. **Backup** your old setup.py
2. **Extract** all configuration values
3. **Map** them to pyproject.toml sections:
   - `name`, `version`, etc. → `[project]`
   - `install_requires` → `[project] dependencies`
   - `extras_require` → `[project.optional-dependencies]`
   - `entry_points` → `[project.scripts]`
   - `packages` → `[tool.setuptools.packages.find]`
4. **Test** with: `pip install -e .`
5. **Verify** all functionality works

## Troubleshooting

### "No module named setuptools"
```bash
pip install --upgrade setuptools wheel
```

### "pyproject.toml not found"
Make sure you're in the project root directory.

### Installation fails with old pip
```bash
pip install --upgrade pip  # Need pip >= 21.0
```

### Tests not discovered
Make sure test files match patterns in `[tool.pytest.ini_options]`.

## Resources

- [PEP 517 - Build System](https://peps.python.org/pep-0517/)
- [PEP 518 - pyproject.toml](https://peps.python.org/pep-0518/)
- [PEP 621 - Project Metadata](https://peps.python.org/pep-0621/)
- [Packaging Tutorial](https://packaging.python.org/tutorials/packaging-projects/)
- [setuptools pyproject.toml guide](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html)
