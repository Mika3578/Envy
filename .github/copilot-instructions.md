# GitHub Copilot Instructions for Envy

## Project Overview
Envy is a multi-network P2P filesharing and BitTorrent client for Windows, written in C++ using MFC (Microsoft Foundation Classes).

## Code Standards and Best Practices

### C++ Standards
- **Language Standard**: Use C++20 features where appropriate
- **Platform**: Windows (Win32/x64)
- **Framework**: MFC (Microsoft Foundation Classes)
- **Character Set**: Unicode (UTF-16)

### Coding Conventions
1. **Naming Conventions**:
   - Classes: PascalCase (e.g., `CDownloadTask`, `CLibraryFile`)
   - Member variables: m_prefix with camelCase (e.g., `m_nFileSize`, `m_pConnection`)
   - Functions: PascalCase (e.g., `OnDownload`, `GetFileSize`)
   - Constants: ALL_CAPS with underscores (e.g., `MAX_BUFFER_SIZE`)
   - Pointers: p prefix (e.g., `pFile`, `pConnection`)
   - Counts/Numbers: n prefix (e.g., `nCount`, `nSize`)
   - Strings: str prefix (e.g., `strFileName`, `strPath`)

2. **Memory Management**:
   - Use smart pointers (std::unique_ptr, std::shared_ptr) for modern code
   - For MFC objects, follow MFC memory management patterns
   - Always check for nullptr before dereferencing
   - Use RAII principles for resource management

3. **Error Handling**:
   - Use exceptions for exceptional cases
   - Check return values for Win32 API calls
   - Use ASSERT for debug builds to catch logic errors
   - Log errors appropriately with context

4. **Modern C++ Features to Use**:
   - `auto` for type inference when type is obvious
   - Range-based for loops instead of iterator loops
   - `nullptr` instead of NULL
   - `constexpr` for compile-time constants
   - `override` keyword for virtual function overrides
   - `final` keyword where appropriate
   - Structured bindings for multiple return values
   - `std::optional` for optional values
   - `std::string_view` for non-owning string references

5. **Threading**:
   - Use C++20 threading primitives (std::jthread, std::atomic)
   - Prefer std::mutex over CRITICAL_SECTION
   - Use std::lock_guard and std::unique_lock for automatic lock management
   - Document thread safety expectations

### Security Best Practices
- Validate all input from network and user
- Use secure string functions (not strcpy, sprintf)
- Prevent buffer overflows with size checking
- Sanitize file paths to prevent directory traversal
- Use cryptographically secure random numbers for security contexts
- Always use HTTPS/TLS for network communications where possible

### Performance Guidelines
- Minimize allocations in hot paths
- Use const references to avoid unnecessary copies
- Profile before optimizing
- Cache frequently used values
- Use appropriate data structures for the use case

### Code Organization
- Keep functions focused and small (< 50 lines ideally)
- Separate concerns (UI, business logic, network)
- Use header guards or #pragma once
- Include necessary headers explicitly
- Forward declare when possible to reduce compile times

### Documentation
- Use XML documentation comments for public APIs
- Document complex algorithms with inline comments
- Keep comments up-to-date with code changes
- Document thread safety requirements
- Document ownership and lifetime of pointers

### Testing
- Write unit tests for new functionality
- Test edge cases and error conditions
- Include network timeout handling
- Test with various file sizes and types

## Project-Specific Guidelines

### File Handling
- Always use Unicode APIs for file operations
- Handle long paths (> MAX_PATH) correctly
- Check disk space before writing large files
- Use atomic file operations where possible

### Network Code
- Implement proper timeout handling
- Handle network interruptions gracefully
- Validate all received data
- Rate limit operations to prevent abuse

### UI Code
- Keep UI responsive with background operations
- Use MFC message maps properly
- Update UI on main thread only
- Provide progress feedback for long operations

### BitTorrent Implementation
- Follow BEP (BitTorrent Enhancement Proposals)
- Implement proper peer protocol handling
- Support DHT and PEX
- Handle corrupted torrent data

## When Suggesting Changes
1. Maintain backward compatibility where possible
2. Consider Windows XP through Windows 11 support
3. Test on both 32-bit and 64-bit builds
4. Check for existing patterns in the codebase
5. Respect the existing architecture
6. Consider performance implications for large files/networks

## Avoid
- Breaking changes to file formats or protocols
- Platform-specific code without proper #ifdef guards
- Blocking the UI thread
- Memory leaks (especially with COM objects)
- Unsafe string operations
- Unhandled exceptions that could crash the app

## Helpful Context
- This is a mature codebase with legacy components
- Performance is critical for large downloads and many peers
- Network resilience is essential
- User data must be protected
