# Naming Conventions

## Classes and Structs

```cpp
// ✅ Good: PascalCase with C prefix for MFC classes
class CDownloadTask;
class CHashFunction;
class CLibraryFile;

// ✅ Good: Plain structs without C prefix
struct FileMetadata;
struct NetworkConfig;
struct DownloadProgress;
```

## Member Variables

### Prefixes
```cpp
class CExample {
private:
    // String members: m_str prefix
    CString m_strFileName;
    CString m_strPath;
    CString m_strUrl;
    
    // Numeric members: m_n prefix
    int m_nCount;
    DWORD m_nFileSize;
    size_t m_nBufferSize;
    WORD m_nPort;
    
    // Boolean members: m_b prefix
    bool m_bIsActive;
    bool m_bCompleted;
    bool m_bConnected;
    
    // Pointer members: m_p prefix
    CFile* m_pFile;
    CConnection* m_pConnection;
    std::unique_ptr<CData> m_pData;
    
    // Reference members: m_ prefix (rare)
    CSettings& m_Settings;
    
    // Smart pointers: m_p prefix
    std::unique_ptr<CResource> m_pResource;
    std::shared_ptr<CSharedData> m_pSharedData;
};
```

## Functions and Methods

```cpp
// ✅ Good: Public methods - PascalCase
void StartDownload();
bool IsCompleted() const;
CString GetFileName() const;
void SetPriority(Priority priority);

// ✅ Good: Private methods - PascalCase
void UpdateProgress();
void CleanupResources();
bool ValidateState() const;

// ✅ Good: Event handlers (MFC style)
afx_msg void OnDownloadComplete();
afx_msg LRESULT OnProgressUpdate(WPARAM wParam, LPARAM lParam);
```

## Local Variables and Parameters

```cpp
// ✅ Good: Local variables - camelCase with type prefix
void ProcessFile(const CString& strPath) {
    CString strName = GetFileName(strPath);
    int nSize = GetFileSize(strPath);
    bool bExists = FileExists(strPath);
    CFile* pFile = nullptr;
    
    // Loop variables
    for (int i = 0; i < nCount; i++) { ... }
    
    // References
    auto& settings = GetSettings();
}
```

## Constants and Enums

```cpp
// ✅ Good: Constants - ALL_CAPS with underscores
constexpr size_t MAX_BUFFER_SIZE = 8192;
constexpr DWORD DEFAULT_TIMEOUT = 30000;
const int PROTOCOL_VERSION = 1;

// ✅ Good: Enum classes - PascalCase
enum class DownloadState {
    Idle,
    Connecting,
    Downloading,
    Completed,
    Failed
};

// ✅ Good: MFC-style enums (legacy)
enum {
    ID_DOWNLOAD_START = 1001,
    ID_DOWNLOAD_PAUSE = 1002,
    ID_DOWNLOAD_CANCEL = 1003
};
```

## Macros

```cpp
// ✅ Good: Project-wide macros - ALL_CAPS
#define ENVY_VERSION_MAJOR 4
#define ENVY_VERSION_MINOR 1

// ✅ Good: Debug macros
#ifdef _DEBUG
#define TRACE_LINE() TRACE(_T("Line %d in %s\n"), __LINE__, __FILE__)
#endif
```

## File Naming

```cpp
// ✅ Good: File names match class names
// Class: CDownloadTask
// Files: DownloadTask.h, DownloadTask.cpp

// ✅ Good: Related files
// DownloadTask.h
// DownloadTask.cpp
// DownloadTaskHelpers.cpp
// DownloadTaskTests.cpp
```

## Type Prefixes Summary

| Prefix | Type | Example |
|--------|------|---------|
| `str` | String | `strFileName`, `strPath` |
| `n` | Number/Count | `nCount`, `nSize`, `nPort` |
| `b` | Boolean | `bIsActive`, `bCompleted` |
| `p` | Pointer | `pFile`, `pConnection` |
| `m_` | Member variable | `m_strName`, `m_nCount` |
| `m_str` | Member string | `m_strFileName` |
| `m_n` | Member number | `m_nFileSize` |
| `m_b` | Member boolean | `m_bIsActive` |
| `m_p` | Member pointer | `m_pFile` |

## Avoid

- Inconsistent naming (mixing styles)
- Single letter variables (except loop counters: `i`, `j`, `k`)
- Abbreviations that aren't clear
- Hungarian notation for modern C++ types (use for MFC types)
- Underscores in class names (use PascalCase)
