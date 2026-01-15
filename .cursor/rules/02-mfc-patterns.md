# MFC Patterns and Conventions

## MFC Class Naming

### Class Prefix
```cpp
// ✅ Good: MFC classes use C prefix
class CDownloadTask;
class CLibraryFile;
class CConnection;

// Plain structs without C prefix
struct FileMetadata;
struct NetworkConfig;
```

### MFC Macros
```cpp
// ✅ Good: Use MFC macros
class CDownloadTask : public CObject {
    DECLARE_DYNAMIC(CDownloadTask)
    DECLARE_MESSAGE_MAP()
    
public:
    DECLARE_SERIAL(CDownloadTask)
};
```

## Member Variables

### MFC Naming Prefixes
```cpp
class CExample {
private:
    // String members
    CString m_strFileName;
    CString m_strPath;
    
    // Numeric members
    int m_nCount;
    DWORD m_nFileSize;
    size_t m_nBufferSize;
    
    // Boolean members
    bool m_bIsActive;
    bool m_bCompleted;
    
    // Pointer members
    CFile* m_pFile;
    std::unique_ptr<CData> m_pData;
    
    // Reference members (rare)
    CSettings& m_Settings;
};
```

## Message Maps

### Event Handlers
```cpp
// ✅ Good: MFC message map style
class CDownloadWindow : public CDialog {
    DECLARE_MESSAGE_MAP()
    
public:
    afx_msg void OnDownloadStart();
    afx_msg void OnDownloadPause();
    afx_msg LRESULT OnProgressUpdate(WPARAM wParam, LPARAM lParam);
    afx_msg void OnBnClickedOk();
};

BEGIN_MESSAGE_MAP(CDownloadWindow, CDialog)
    ON_COMMAND(ID_DOWNLOAD_START, &CDownloadWindow::OnDownloadStart)
    ON_COMMAND(ID_DOWNLOAD_PAUSE, &CDownloadWindow::OnDownloadPause)
    ON_MESSAGE(WM_PROGRESS_UPDATE, &CDownloadWindow::OnProgressUpdate)
    ON_BN_CLICKED(IDOK, &CDownloadWindow::OnBnClickedOk)
END_MESSAGE_MAP()
```

## GUI Resource De-duplication (Non-negotiable)

**⚠️ HARD RULE: This process is mandatory before creating any new GUI resource.**

Before creating any new GUI resource (dialog, control, menu, toolbar, accelerators, icons/bitmaps, string/table entries), you MUST first enumerate and verify existing resources to avoid duplicates.

### Required Process

#### Step 1: Search Existing Resources
Search existing resources by:
- **Resource ID** (both numeric and symbolic)
- **Resource name**
- **Caption/title text**
- **Usage strings**

Also search related code references:
- `Create/Load/FindResource` calls
- `DDX/DDV` macros
- `GetDlgItem` calls
- `ON_COMMAND/ON_UPDATE_COMMAND_UI` handlers
- Dialog class constructors and `DoModal` calls

#### Step 2: Prefer Reuse
- **Prefer reusing or extending an existing resource** over creating a new one
- Check if an existing dialog/control can be extended with additional functionality
- Verify if a similar resource exists that can be adapted

#### Step 3: When New Resource is Unavoidable
If a new resource is truly necessary:
- **Allocate an unused ID** by scanning current ID ranges and nearby groups
- Keep IDs contiguous per feature/module
- Ensure no collision in `.rc` and `.h` resource defines
- Avoid duplicate captions that could confuse users
- **Document the reason** for creation and where it is used (file path + class/function)

#### Step 4: Output Requirement
For every new resource, you MUST list:
- **"Existing resources checked"** - IDs/names searched
- **"Chosen free slot / ID"** - The specific ID allocated
- **"Where used"** - Evidence pointers: file path + symbol/class/function

### Hard Rule Enforcement

**No new GUI resource is allowed without Step 1 evidence.**

If you cannot verify existing resources:
- Mark it as **"Unverified / TBD"**
- **Do NOT create the resource** until verification is complete
- Document what verification was attempted

### Example Verification Output

```cpp
// ✅ Good: Proper resource verification documentation
// Existing resources checked:
//   - IDD_DOWNLOAD_DIALOG (ID 101) - used in DlgDownload.cpp
//   - IDD_DOWNLOAD_MONITOR (ID 102) - used in DlgDownloadMonitor.cpp
//   - Searched Resource.h: IDs 100-150 range
//   - Searched Envy.rc: Dialog definitions
//   - Searched codebase: "Download" dialog references
//
// Chosen free slot / ID: IDD_DOWNLOAD_FILTER (ID 103)
//
// Where used:
//   - File: Envy/DlgDownloadFilter.cpp
//   - Class: CDlgDownloadFilter
//   - Function: CDlgDownloadFilter::DoModal()
```

```cpp
// ❌ Bad: No verification evidence
// Just creating IDD_NEW_DIALOG without checking existing resources
IDD_NEW_DIALOG DIALOGEX 0, 0, 200, 100
```

### Resource Search Tools

When searching for existing resources:
- Use `grep` to search `.rc` files for resource definitions
- Search `Resource.h` for ID definitions
- Search codebase for resource ID usage
- Check dialog class files for `IDD_*` references
- Verify menu/toolbar IDs in message maps

## MFC String Handling

### CString Usage
```cpp
// ✅ Good: CString for MFC code
CString strFileName = _T("file.txt");
CString strPath;
strPath.Format(_T("Path: %s"), (LPCTSTR)strFileName);

// ✅ Good: Use GetString() for std::string_view
std::wstring_view view(strFileName.GetString());

// ❌ Bad: Mixing std::string with MFC
std::string str = "file.txt";  // Avoid in MFC code
```

### Unicode Support
```cpp
// ✅ Good: Always use Unicode
CString strPath = _T("C:\\Path\\To\\File.txt");
LPCTSTR pszPath = (LPCTSTR)strPath;

// ✅ Good: Use _T() macro for string literals
CString str = _T("Hello World");

// ❌ Bad: ANSI strings
char* str = "Hello";  // Avoid
```

## MFC Collections

### CAtlList Usage
```cpp
// ✅ Good: MFC collections
CAtlList<CString> fileList;
POSITION pos = fileList.GetHeadPosition();
while (pos != nullptr) {
    CString strFile = fileList.GetNext(pos);
    ProcessFile(strFile);
}

// ✅ Better: Modern iteration when possible
std::vector<CString> files;
for (const auto& file : files) {
    ProcessFile(file);
}
```

## MFC Error Handling

### Win32 API Errors
```cpp
// ✅ Good: Check Win32 API return values
HANDLE hFile = CreateFile(strPath, GENERIC_READ, 0, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
if (hFile == INVALID_HANDLE_VALUE) {
    DWORD dwError = GetLastError();
    theApp.Message(MSG_ERROR, _T("CreateFile failed: %lu"), dwError);
    return false;
}
```

### MFC Object Validation
```cpp
// ✅ Good: MFC object error checking
CFile file;
if (!file.Open(strPath, CFile::modeRead)) {
    theApp.Message(MSG_ERROR, _T("Failed to open file: %s"), (LPCTSTR)strPath);
    return false;
}
```

## Debug Macros

### ASSERT and VERIFY
```cpp
// ✅ Good: Debug assertions
ASSERT(pConnection != nullptr);
ASSERT(nSize > 0);

// ✅ Good: Release-safe checks
VERIFY(file.Open(strPath, CFile::modeRead));

// ✅ Good: Debug logging
#ifdef _DEBUG
    TRACE(_T("Processing file: %s\n"), (LPCTSTR)strPath);
#endif
```

## MFC Threading

### UI Thread Operations
```cpp
// ✅ Good: Update UI on main thread
void CMyWindow::UpdateProgress(int nPercent) {
    if (AfxGetMainWnd() != nullptr) {
        AfxGetMainWnd()->PostMessage(WM_UPDATE_PROGRESS, nPercent, 0);
    }
}

// ❌ Bad: Direct UI access from worker thread
void WorkerThread() {
    m_pProgressBar->SetPos(50);  // Unsafe!
}
```

## MFC Compatibility Notes

- Some MFC patterns don't mix well with modern C++ (e.g., CObject-derived classes)
- Use smart pointers where possible, but respect MFC ownership patterns
- Prefer modern C++ for new code, maintain MFC patterns for legacy code
- Document when mixing modern C++ with MFC
