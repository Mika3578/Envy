# Cursor Rules for Envy Project

This directory contains focused, composable rules for the Envy P2P client development. Each rule file addresses a specific aspect of the codebase.

## Rule Files

### 00-project-context.md
Project overview, technology stack, and development philosophy. Start here for context.

### 01-cpp-standards.md
Modern C++ coding standards, language features, and best practices.

### 02-mfc-patterns.md
MFC-specific patterns, conventions, and compatibility guidelines. **⚠️ Includes mandatory GUI Resource De-duplication process (non-negotiable).**

### 03-naming-conventions.md
Naming conventions for classes, variables, functions, and files.

### 04-error-handling.md
Error handling patterns, exception safety, and debugging practices.

### 05-performance.md
Performance guidelines, optimization strategies, and profiling considerations.

### 06-p2p-protocols.md
P2P protocol-specific considerations, network code guidelines, and security.

### 07-documentation.md
Documentation standards, comment styles, and API documentation guidelines.

### 08-development-workflow.md
Development workflow requirements, planning, examples research, and commit standards.

## Usage

These rules are automatically loaded by Cursor and applied to:
- Code generation and suggestions
- Inline edits
- Chat conversations
- Code review assistance

## Best Practices

1. **Keep rules focused**: Each file addresses a specific concern
2. **Be specific**: Provide concrete examples, not vague guidance
3. **Stay current**: Update rules as project evolves
4. **Reference standards**: Link to external documentation when helpful

## Contributing

When adding or modifying rules:
- Keep each rule file under 500 lines
- Include concrete code examples
- Update this README if adding new rule files
- Test that rules work as expected
- Rules can be created, updated, or adapted during development
- Always follow development workflow guidelines

## Related Documentation

- [Code Standards](../docs/contributing/standards.md)
- [Modern C++ Guide](../../.github/MODERN_CPP_GUIDE.md)
- [Contributing Guide](../docs/contributing/guide.md)
