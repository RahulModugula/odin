# Contributing to Odin

Thanks for your interest in contributing to Odin. This guide will help you get set up.

## Prerequisites

- Python 3.12+
- Node.js 22+
- Docker and Docker Compose
- An Anthropic API key

## Local Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/rahulmod/odin.git
   cd odin
   ```

2. **Set up the backend:**

   ```bash
   cd backend
   pip install uv
   uv pip install -e ".[dev]"
   ```

3. **Set up the frontend:**

   ```bash
   cd frontend
   npm install
   ```

4. **Configure environment variables:**

   ```bash
   cp .env.example .env
   # Edit .env and add your ANTHROPIC_API_KEY
   ```

5. **Start dependencies:**

   ```bash
   docker compose up redis -d
   ```

6. **Run the backend:**

   ```bash
   cd backend
   uvicorn app.main:app --reload --port 8000
   ```

7. **Run the frontend:**

   ```bash
   cd frontend
   npm run dev
   ```

## Running Tests

```bash
# Backend tests
cd backend
pytest

# Evaluation suite
cd backend
python -m eval.runner

# Frontend tests
cd frontend
npm test
```

## Code Style

- **Python:** Follow PEP 8. Use type hints for function signatures.
- **TypeScript:** Follow the project ESLint configuration.
- **Commits:** Write clear, concise commit messages. Use present tense ("Add feature" not "Added feature").

## Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Make your changes and ensure all tests pass.
3. Write or update tests for any new functionality.
4. Open a pull request with a clear description of your changes.

## Reporting Issues

Open a GitHub issue with:
- A clear title and description.
- Steps to reproduce the problem.
- Expected vs. actual behavior.
- Relevant logs or error messages.
