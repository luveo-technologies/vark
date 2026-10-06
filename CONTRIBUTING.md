# Contributing to @luveo-tech/vark

Thank you for your interest in contributing to `@luveo-tech/vark`!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/luveo-technologies/vark.git
cd vark

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run type checking
pnpm typecheck
```

## Code Style

- TypeScript strict mode — zero `any` types
- ESLint with `@typescript-eslint` and `eslint-plugin-security`
- All security gates must have 100% test coverage
- All regex patterns must be linear-time (O(n)) — verified by `safe-regex`

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with clear commit messages
3. Ensure all tests pass: `pnpm test`
4. Ensure type checking passes: `pnpm typecheck`
5. Ensure linting passes: `pnpm lint`
6. Submit a PR with a clear description of changes

## Security Contributions

If you discover a security vulnerability, please follow our [security policy](SECURITY.md) before submitting a PR.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
