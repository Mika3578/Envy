//
// Plugin.h : Declaration of the CPlugin
//

#pragma once

#include "SearchExport.h"

// CPlugin - This class implements the plugin functionality.

class ATL_NO_VTABLE CPlugin :
    public CComObjectRootEx<CComMultiThreadModel>,
    public CComCoClass<CPlugin, &CLSID_Plugin>,
    public IGeneralPlugin,
    public ICommandPlugin
{
public:
    CPlugin() :
        m_nCmdCheck(0)  // Initialize command check ID to 0
    {
    }

    DECLARE_REGISTRY_RESOURCEID(IDR_PLUGIN)

    BEGIN_COM_MAP(CPlugin)
        COM_INTERFACE_ENTRY(IGeneralPlugin)
        COM_INTERFACE_ENTRY(ICommandPlugin)
    END_COM_MAP()

    DECLARE_PROTECT_FINAL_CONSTRUCT()

    // FinalConstruct - Perform any final construction tasks
    HRESULT FinalConstruct()
    {
        return S_OK;
    }

    // FinalRelease - Perform any final release tasks
    void FinalRelease()
    {
        m_pApplication.Release();
        m_pUserInterface.Release();
    }

protected:
    CComPtr<IApplication> m_pApplication;   // Pointer to Envy application
    CComPtr<IUserInterface> m_pUserInterface; // Pointer to Envy GUI
    UINT m_nCmdCheck;   // Command ID

    // Export - Export data to GenericView
    HRESULT Export(IGenericView* pGenericView, LONG nCount);

    // InsertCommand - Insert a menu item only if no item is present
    void InsertCommand(LPCTSTR szTitle, const LPCWSTR* szMenu, UINT nID);

    // IGeneralPlugin Interface Methods
public:
    STDMETHOD(SetApplication)(
        /* [in] */ IApplication __RPC_FAR *pApplication);
    STDMETHOD(QueryCapabilities)(
        /* [in] */ DWORD __RPC_FAR *pnCaps);
    STDMETHOD(Configure)();
    STDMETHOD(OnSkinChanged)();

    // ICommandPlugin Interface Methods
public:
    STDMETHOD(RegisterCommands)();
    STDMETHOD(InsertCommands)();
    STDMETHOD(OnUpdate)(
        /* [in] */ UINT nCommandID,
        /* [out][in] */ TRISTATE __RPC_FAR *pbVisible,
        /* [out][in] */ TRISTATE __RPC_FAR *pbEnabled,
        /* [out][in] */ TRISTATE __RPC_FAR *pbChecked);
    STDMETHOD(OnCommand)(
        /* [in] */ UINT nCommandID);
};

OBJECT_ENTRY_AUTO(__uuidof(Plugin), CPlugin)
