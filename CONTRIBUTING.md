# Contributing to @pq-jwt/express

Thank you for helping make post-quantum authentication accessible and easy to use for every developer.

## Before you start

- Open an issue first for any significant change.
- All contributions must keep the full test suite passing.
- Do not implement custom cryptographic primitives or bypass `@pq-jwt/core`.

## Setup

```bash
git clone https://github.com/pq-jwt/PQ-JWT-Express
cd PQ-JWT-Express
npm install
npm test
```

## Making a change

1. Fork the repo.
2. Create a branch: `git checkout -b feat/your-feature`.
3. Make your change.
4. Run tests: `npm test`.
5. Open a Pull Request against `main`.

## What we welcome

- Bug fixes with a failing test that proves the fix.
- Documentation and examples improvements.
- Performance improvements that do not alter standard middleware behaviors.
- New test cases for edge cases in token extraction, role authorization, or custom handlers.

## What we do not accept

- Custom cryptographic implementations.
- Breaking API changes without prior discussion.
- Changes that reduce test coverage.
