#!/bin/bash
# Run tests with coverage
cd "$(dirname "$0")"

if [ -x "venv/bin/python" ]; then
    PY="venv/bin/python"
else
    PY="${PYTHON:-python3}"
fi

echo "Running tests with coverage report..."
"$PY" -m pytest tests/ --cov=app --cov-report=html --cov-report=term

echo ""
echo "Coverage report generated in htmlcov/index.html"
