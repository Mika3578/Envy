# Envy Unit Tests

**Status:** Framework setup complete, tests to be implemented

## Testing Framework

This directory contains unit tests for the Envy project using **Google Test** framework.

## Setup

### Prerequisites
- CMake 3.20+
- Visual Studio 2026 (or compatible)
- Git (for fetching Google Test)

### Building Tests

```powershell
# Configure CMake with tests enabled
cmake -B build -S . -DBUILD_TESTS=ON

# Build tests
cmake --build build --config Release --target HashLibTests

# Run tests
cd build
ctest --config Release --verbose
```

### Running Individual Tests

```powershell
.\build\bin\Release\HashLibTests.exe
```

## Test Structure

```
tests/
├── HashLib/          # HashLib tests (to be created)
│   ├── test_md5.cpp
│   ├── test_sha.cpp
│   └── test_ed2k.cpp
├── Network/          # Network tests (to be created)
├── Library/          # Library tests (to be created)
└── CMakeLists.txt    # Test configuration
```

## Writing Tests

### Example Test

```cpp
#include <gtest/gtest.h>
#include "HashLib.h"
#include "MD5.h"

TEST(MD5Test, BasicHash) {
    CMD5 md5;
    md5.Add("Hello, World!", 13);
    md5.Finish();
    
    EXPECT_EQ(md5.GetHash().GetString(), "65a8e27d8879283831b664bd8b7f0ad4");
}
```

## Integration with CI/CD

Tests are automatically run in CI/CD pipeline when `BUILD_TESTS=ON` is set.

## Coverage Goals

- **Phase 1:** 30% coverage (critical components)
- **Phase 2:** 60% coverage (all core components)
- **Phase 3:** 80% coverage (complete)

## Next Steps

1. Implement HashLib tests
2. Implement Network tests
3. Implement Library tests
4. Set up coverage reporting
5. Integrate into CI/CD
