#!/bin/bash
# Run tests with coverage

cd "$(dirname "$0")"

echo "Running tests with coverage report..."
venv/bin/python -m pytest tests/ --cov=app --cov-report=html --cov-report=term

echo ""
echo "Coverage report generated in htmlcov/index.html"
