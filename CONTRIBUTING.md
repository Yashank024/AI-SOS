# Contributing to AI SOS

Thank you for your interest in contributing to **AI SOS**! We welcome bug fixes, documentation improvements, performance optimizations, and new framework adapters.

---

## Development Setup

### 1. Fork & Clone Repository

```bash
git clone https://github.com/your-username/AI-SOS.git
cd AI-SOS
```

### 2. Create Virtual Environment & Install Dependencies

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -e ".[dev]"
```

---

## Code Quality Standards

1. **Type Hints**: All functions and methods must include explicit PEP 484 type hints.
2. **Coding Style**: Follow PEP 8 guidelines. Keep line lengths under 100 characters.
3. **No Breaking Changes**: Core attachment APIs (`security.attach(app)`) must maintain 100% backward compatibility.
4. **Test Coverage**: All new features or bug fixes must include corresponding `pytest` test cases. Overall project coverage must remain **>= 90%**.

---

## Running Tests

Run the full test suite locally:

```bash
python -m pytest -v --cov=aisos
```

Run performance benchmark validation:

```bash
python -m tests.benchmark
```

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names (`feat/custom-adapter`, `fix/fastapi-body-stream`, `docs/api-update`).
2. **Commit Messages**: Write clear commit messages following Conventional Commits format (`feat:`, `fix:`, `docs:`, `perf:`).
3. **CI Passing**: Ensure GitHub Actions CI checks pass cleanly before requesting review.
