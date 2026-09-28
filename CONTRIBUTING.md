# Contributing to edgeprint

Thank you for your interest in contributing to the edgeprint project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Adding WAF Fingerprints](#adding-waf-fingerprints)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs. actual behavior
- **Python version** and OS
- **Sample input files** (if applicable and safe to share)
- **Error messages** or logs

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case** for the enhancement
- **Expected behavior** and benefits
- **Alternative solutions** you've considered
- **Impact on existing functionality**

### Adding WAF Fingerprints

See [Adding WAF Fingerprints](#adding-waf-fingerprints) section below.

### Improving Documentation

Documentation improvements are always appreciated:

- Fix typos or clarify existing documentation
- Add examples or usage scenarios
- Improve code comments
- Create tutorials or guides

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- pip

### Setup Steps

1. **Fork the repository** on GitHub

2. **Clone your fork:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/Edgeprint.git
   cd Edgeprint
   ```

3. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install development dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

5. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Contribution Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use **Black** for code formatting (line length: 100)
- Use **Ruff** for linting
- Add type hints to all functions
- Write docstrings for modules, classes, and functions

**Format your code:**
```bash
black edgeprint/
ruff check edgeprint/ --fix
```

### Type Checking

Run mypy to ensure type correctness:
```bash
mypy edgeprint/
```

### Documentation

- Add docstrings to all new functions and classes
- Update README.md if adding new features
- Include usage examples for new functionality

### Commit Messages

Write clear, descriptive commit messages:

```
Add Barracuda WAF fingerprint

- Add header patterns for Barracuda WAF
- Include cookie signatures
- Add test case for detection
```

**Guidelines:**
- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests

## Adding WAF Fingerprints

### Guidelines for Fingerprints

When adding new WAF fingerprints, follow these guidelines:

1. **Use Publicly Available Information Only**
   - Only include patterns from official documentation or public knowledge
   - Do not include proprietary or reverse-engineered signatures
   - Cite sources when possible

2. **Minimize False Positives**
   - Use multiple indicators when possible
   - Test against non-WAF responses
   - Consider generic vs. specific patterns

3. **Provide Documentation**
   - Document the source of the fingerprint
   - Explain the reasoning behind the patterns
   - Include example responses (redacted if necessary)

### Fingerprint Structure

Add fingerprints to `edgeprint/data/fingerprints/<vendor>.json`. There is no build
step — the files are read directly, so what you edit is what ships.

```json
{
  "vendor": "VendorName WAF",
  "layers": ["waf"],
  "references": ["https://vendor.example/docs/response-headers"],
  "signals": [
    {
      "type": "header",
      "key": "x-vendor*",
      "contains": "",
      "weight": 0.25,
      "source": "edgeprint",
      "verified_against": "tests/fixtures/positive/vendor_200.txt"
    },
    {
      "type": "cookie",
      "name_prefix": "vendor_session",
      "weight": 0.20,
      "source": "edgeprint",
      "verified_against": "tests/fixtures/positive/vendor_200.txt"
    }
  ]
}
```

Use a `*` suffix whenever the real header name carries a suffix. Exact-key matching
is the single most common source of missed detections.

### Every fingerprint needs a fixture

**A fingerprint without a captured response will not be merged.** This is the rule
that keeps the database honest — the previous fingerprint set contained signals that
had never matched a real response, including an Akamai entry that could not fire at all.

1. Save the response to `tests/fixtures/positive/<vendor>_<status>.txt`
2. Add a row to `tests/fixtures/manifest.json`:

   ```json
   {
     "file": "positive/vendor_200.txt",
     "format": "raw",
     "label_source": "synthetic",
     "expect_layers": ["waf"],
     "expect_vendor": "VendorName WAF",
     "expect_exit": 2
   }
   ```

3. Run `./check.sh` — the suite is generated from the manifest and validates every
   fingerprint, so your case is picked up automatically. No test code to write.

All of `expect_layers` and `expect_exit` are required — the suite reads them at
import time, so a row missing either aborts collection of the whole module.
`expect_exit` is 2 when a `waf` layer is expected, 3 for edge without WAF, 0 for
negatives.

Set `label_source` honestly: `synthetic` for hand-built from documentation, `lab` for
a WAF you stood up yourself, `cname` or `cidr` for a live host labelled by DNS or
published IP range. Lab and infrastructure labels are worth far more than synthetic
ones, because they are known rather than inferred.

If your fingerprint could plausibly fire on an unprotected origin, add a matching
negative fixture under `tests/fixtures/negative/` too.

### Testing Fingerprints

Before submitting:

1. **Test with real samples:**
   ```bash
   edgeprint analyze -i test_sample.txt --verbose
   ```

2. **Verify detection:**
   - The fingerprint identifies the WAF and ranks it first
   - It does not fire on the negative fixtures: `pytest -k negative`

3. **Document your testing:**
   - Include test methodology in PR description
   - Provide sanitized sample responses
   - List any edge cases discovered

### Example Contribution

```python
# In fingerprints.py
{
    "vendor": "Example WAF Pro",
    "header_contains": [
        ("server", "examplewaf"),
        ("x-example-ray", ""),
        ("x-example-cache", ""),
    ],
    "cookie_contains": ["example_waf_", "ewaf_session"],
    "body_contains": ["example waf protection", "request blocked by example"]
}
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** if needed
2. **Ensure all code follows** style guidelines
3. **Run type checking** with mypy
4. **Test your changes** thoroughly
5. **Update CHANGELOG.md** with your changes
6. **Create a pull request** with:
   - Clear title and description
   - Reference to related issues
   - Summary of changes
   - Testing methodology

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] WAF fingerprint addition

## Changes Made
- List key changes
- Include any breaking changes

## Testing
- Describe testing performed
- Include test results

## Checklist
- [ ] Code follows project style guidelines
- [ ] Documentation has been updated
- [ ] Changes have been tested
- [ ] CHANGELOG.md has been updated
```

### Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged
- You'll be credited in the CHANGELOG

## Questions?

If you have questions about contributing:

- Open an issue with the `question` label
- Reach out to the maintainers
- Check existing documentation

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- Project documentation
- Release notes (for significant contributions)

Thank you for contributing to make security testing safer and more accessible!

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
