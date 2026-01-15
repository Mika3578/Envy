# Performance Guidelines

## Memory Management

### Smart Pointers
```cpp
// ✅ Good: Smart pointers for automatic management
std::unique_ptr<CData> pData = std::make_unique<CData>();
auto pShared = std::make_shared<CResource>();

// ❌ Bad: Unnecessary copies
void ProcessData(CData data);  // Copies parameter
void ProcessData(const CData& data); // ✅ Reference instead
void ProcessData(CData&& data); // ✅ Move when appropriate
```

### Reserve Capacity
```cpp
// ✅ Good: Reserve capacity when size is known
std::vector<CString> files;
files.reserve(expectedCount);
for (int i = 0; i < expectedCount; i++) {
    files.push_back(GetFileName(i));
}

// ❌ Bad: Multiple reallocations
std::vector<CString> files;  // Will reallocate multiple times
for (int i = 0; i < expectedCount; i++) {
    files.push_back(GetFileName(i));  // Potential reallocation each time
}
```

## Loops and Algorithms

### Range-Based For
```cpp
// ✅ Good: Range-based for
for (const auto& file : files) {
    ProcessFile(file);
}

// ✅ Good: Standard algorithms
auto it = std::find_if(files.begin(), files.end(),
    [](const CFile& f) { return f.GetSize() > 1000000; });

// ❌ Bad: Manual loops when algorithms exist
for (size_t i = 0; i < files.size(); i++) {
    if (files[i].GetSize() > 1000000) {
        // Process
        break;
    }
}
```

### Const References
```cpp
// ✅ Good: Use const references to avoid copies
void ProcessFile(const CString& strPath) {
    // No copy made
}

// ✅ Good: Move semantics when appropriate
void ProcessFile(CString&& strPath) {
    // Takes ownership, no copy
}

// ❌ Bad: Unnecessary copies
void ProcessFile(CString strPath) {  // Copies the string
    // ...
}
```

## Hot Path Optimization

### Thread-Local Storage
```cpp
// ✅ Good: Minimize allocations in hot paths
class CPacketProcessor {
public:
    bool ProcessPacket(CBuffer* pBuffer) {
        static thread_local std::vector<BYTE> tempBuffer;
        tempBuffer.resize(pBuffer->m_nLength);
        memcpy(tempBuffer.data(), pBuffer->m_pBuffer, pBuffer->m_nLength);
        return ProcessData(tempBuffer);
    }
};
```

### Avoid Repeated Allocations
```cpp
// ✅ Good: Reuse buffers
class CNetworkProcessor {
private:
    std::vector<BYTE> m_buffer;  // Reused buffer
    
public:
    void ProcessData(const BYTE* pData, size_t nSize) {
        m_buffer.resize(nSize);
        memcpy(m_buffer.data(), pData, nSize);
        // Process buffer
    }
};

// ❌ Bad: Allocate on every call
void ProcessData(const BYTE* pData, size_t nSize) {
    std::vector<BYTE> buffer(nSize);  // Allocation every time
    memcpy(buffer.data(), pData, nSize);
    // Process buffer
}
```

## String Operations

### String View
```cpp
// ✅ Good: Use string_view for non-owning references
bool StartsWith(std::wstring_view str, std::wstring_view prefix) {
    if (str.length() < prefix.length())
        return false;
    return str.substr(0, prefix.length()) == prefix;
}

// Usage - no string copies
CString strFileName = _T("file.txt");
if (StartsWith(strFileName.GetString(), L"file")) {
    // Process
}

// ❌ Bad: Unnecessary string copies
bool StartsWith(const CString& str, const CString& prefix) {
    // Creates temporary strings for comparison
    return str.Left(prefix.GetLength()) == prefix;
}
```

### String Formatting
```cpp
// ✅ Good: Pre-allocate formatted strings
CString strMessage;
strMessage.Preallocate(256);  // Reserve space
strMessage.Format(_T("Processing file: %s (Size: %llu bytes)"), 
                 (LPCTSTR)strFileName, nFileSize);

// ❌ Bad: Multiple reallocations
CString strMessage;
strMessage.Format(_T("Processing file: %s"), (LPCTSTR)strFileName);
strMessage += _T(" (Size: ");
// Multiple string operations cause reallocations
```

## Network Performance

### Buffer Management
```cpp
// ✅ Good: Reuse network buffers
class CNetworkConnection {
private:
    std::vector<BYTE> m_recvBuffer;
    static constexpr size_t BUFFER_SIZE = 8192;
    
public:
    bool ReceiveData() {
        m_recvBuffer.resize(BUFFER_SIZE);
        int nReceived = recv(m_hSocket, 
                             (char*)m_recvBuffer.data(), 
                             BUFFER_SIZE, 0);
        if (nReceived > 0) {
            m_recvBuffer.resize(nReceived);
            ProcessBuffer(m_recvBuffer);
        }
        return nReceived > 0;
    }
};
```

### Batch Operations
```cpp
// ✅ Good: Batch operations when possible
void UpdateMultipleFiles(const std::vector<CString>& files) {
    BeginBatchUpdate();
    for (const auto& file : files) {
        UpdateFile(file);
    }
    EndBatchUpdate();  // Single UI update
}

// ❌ Bad: Individual updates
void UpdateMultipleFiles(const std::vector<CString>& files) {
    for (const auto& file : files) {
        UpdateFile(file);  // Each call updates UI
    }
}
```

## Caching

### Cache Frequently Used Values
```cpp
// ✅ Good: Cache expensive computations
class CFileInfo {
private:
    mutable std::optional<CString> m_cachedHash;
    
public:
    CString GetHash() const {
        if (!m_cachedHash.has_value()) {
            m_cachedHash = ComputeHash();  // Expensive operation
        }
        return m_cachedHash.value();
    }
};
```

## Profiling Guidelines

- Profile before optimizing
- Focus on hot paths (frequently called code)
- Measure actual performance, don't guess
- Consider both CPU and memory usage
- Test with realistic data sizes

## Avoid

- Premature optimization
- Unnecessary allocations in loops
- Copying large objects unnecessarily
- String concatenation in loops
- Ignoring compiler optimizations
- Optimizing without profiling
