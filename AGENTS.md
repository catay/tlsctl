# AGENTS.md

This repository may be worked on by AI coding agents.
All agents must follow the guidelines below to ensure consistency, quality, and maintainability.

---

## 🎯 Goals for AI Coding Agents

When assisting on this project, agents should:

### Primary Goals

- Follow idiomatic **Go style**
- Produce **readable** and **maintainable** code
- Keep dependencies **minimal**
- Design for **future extensibility**
- Ensure **robust error handling** and **edge case testing**

---

## 🧭 Coding Standards

- Use standard Go formatting (`gofmt`) at all times
- Prefer clear, explicit code over clever or obscure constructs
- Avoid premature optimization
- Keep functions small and focused
- Use interfaces thoughtfully and only where they add real valu"

---

## 🌿 Git Workflow

- Use **Conventional Commits** format:
  `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, etc.

- For each new feature:
  - Create a **separate branch** named using the same conventional prefix
    Example: `feat/add-auth-middleware`

- Before committing:
  - Ensure all tests pass successfully
  - Run linters and formatters if available

- Commit strategy:
  - Squash feature work into **one clean commit**
  - Keep commit messages descriptive and scoped

- Merging:
  - Always request **explicit approval** before merging into `main`

---

## 📚 Documentation

- Ensure all new features are properly documented
- Update:
  - README (if user-facing)
  - Godoc comments for exported types/functions
- Add usage examples where helpful

---

## 🧪 Testing

- Add tests for:
  - New features
  - Bug fixes
  - Edge cases
- Prefer table-driven tests where appropriate
- Avoid brittle or overly coupled tests

---

## 🤖 Agent Conduct

- Do not introduce unnecessary abstractions
- Do not add dependencies without clear justification
- Prefer standard library solutions when possible
- Keep changes scoped to the task at hand

---

By contributing to this repository, agents agree to follow these guidelines to keep the codebase clean, stable, and easy to evolve.
