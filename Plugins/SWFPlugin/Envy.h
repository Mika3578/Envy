

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for ..\Common\Envy.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __Envy_h__
#define __Envy_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifndef __IApplication_FWD_DEFINED__
#define __IApplication_FWD_DEFINED__
typedef interface IApplication IApplication;

#endif 	/* __IApplication_FWD_DEFINED__ */


#ifndef __ISXMLNode_FWD_DEFINED__
#define __ISXMLNode_FWD_DEFINED__
typedef interface ISXMLNode ISXMLNode;

#endif 	/* __ISXMLNode_FWD_DEFINED__ */


#ifndef __ISXMLElement_FWD_DEFINED__
#define __ISXMLElement_FWD_DEFINED__
typedef interface ISXMLElement ISXMLElement;

#endif 	/* __ISXMLElement_FWD_DEFINED__ */


#ifndef __ISXMLElements_FWD_DEFINED__
#define __ISXMLElements_FWD_DEFINED__
typedef interface ISXMLElements ISXMLElements;

#endif 	/* __ISXMLElements_FWD_DEFINED__ */


#ifndef __ISXMLAttribute_FWD_DEFINED__
#define __ISXMLAttribute_FWD_DEFINED__
typedef interface ISXMLAttribute ISXMLAttribute;

#endif 	/* __ISXMLAttribute_FWD_DEFINED__ */


#ifndef __ISXMLAttributes_FWD_DEFINED__
#define __ISXMLAttributes_FWD_DEFINED__
typedef interface ISXMLAttributes ISXMLAttributes;

#endif 	/* __ISXMLAttributes_FWD_DEFINED__ */


#ifndef __IGeneralPlugin_FWD_DEFINED__
#define __IGeneralPlugin_FWD_DEFINED__
typedef interface IGeneralPlugin IGeneralPlugin;

#endif 	/* __IGeneralPlugin_FWD_DEFINED__ */


#ifndef __ICommandPlugin_FWD_DEFINED__
#define __ICommandPlugin_FWD_DEFINED__
typedef interface ICommandPlugin ICommandPlugin;

#endif 	/* __ICommandPlugin_FWD_DEFINED__ */


#ifndef __IExecutePlugin_FWD_DEFINED__
#define __IExecutePlugin_FWD_DEFINED__
typedef interface IExecutePlugin IExecutePlugin;

#endif 	/* __IExecutePlugin_FWD_DEFINED__ */


#ifndef __IChatPlugin_FWD_DEFINED__
#define __IChatPlugin_FWD_DEFINED__
typedef interface IChatPlugin IChatPlugin;

#endif 	/* __IChatPlugin_FWD_DEFINED__ */


#ifndef __ISToolbar_FWD_DEFINED__
#define __ISToolbar_FWD_DEFINED__
typedef interface ISToolbar ISToolbar;

#endif 	/* __ISToolbar_FWD_DEFINED__ */


#ifndef __IPluginWindow_FWD_DEFINED__
#define __IPluginWindow_FWD_DEFINED__
typedef interface IPluginWindow IPluginWindow;

#endif 	/* __IPluginWindow_FWD_DEFINED__ */


#ifndef __IPluginWindowOwner_FWD_DEFINED__
#define __IPluginWindowOwner_FWD_DEFINED__
typedef interface IPluginWindowOwner IPluginWindowOwner;

#endif 	/* __IPluginWindowOwner_FWD_DEFINED__ */


#ifndef __ILibraryBuilderPlugin_FWD_DEFINED__
#define __ILibraryBuilderPlugin_FWD_DEFINED__
typedef interface ILibraryBuilderPlugin ILibraryBuilderPlugin;

#endif 	/* __ILibraryBuilderPlugin_FWD_DEFINED__ */


#ifndef __IImageServicePlugin_FWD_DEFINED__
#define __IImageServicePlugin_FWD_DEFINED__
typedef interface IImageServicePlugin IImageServicePlugin;

#endif 	/* __IImageServicePlugin_FWD_DEFINED__ */


#ifndef __IDownloadPreviewSite_FWD_DEFINED__
#define __IDownloadPreviewSite_FWD_DEFINED__
typedef interface IDownloadPreviewSite IDownloadPreviewSite;

#endif 	/* __IDownloadPreviewSite_FWD_DEFINED__ */


#ifndef __IDownloadPreviewPlugin_FWD_DEFINED__
#define __IDownloadPreviewPlugin_FWD_DEFINED__
typedef interface IDownloadPreviewPlugin IDownloadPreviewPlugin;

#endif 	/* __IDownloadPreviewPlugin_FWD_DEFINED__ */


#ifndef __IDownloadPreviewPlugin2_FWD_DEFINED__
#define __IDownloadPreviewPlugin2_FWD_DEFINED__
typedef interface IDownloadPreviewPlugin2 IDownloadPreviewPlugin2;

#endif 	/* __IDownloadPreviewPlugin2_FWD_DEFINED__ */


#ifndef __IAudioVisPlugin_FWD_DEFINED__
#define __IAudioVisPlugin_FWD_DEFINED__
typedef interface IAudioVisPlugin IAudioVisPlugin;

#endif 	/* __IAudioVisPlugin_FWD_DEFINED__ */


#ifndef __IMediaPlayer_FWD_DEFINED__
#define __IMediaPlayer_FWD_DEFINED__
typedef interface IMediaPlayer IMediaPlayer;

#endif 	/* __IMediaPlayer_FWD_DEFINED__ */


#ifndef __IWrappedPluginControl_FWD_DEFINED__
#define __IWrappedPluginControl_FWD_DEFINED__
typedef interface IWrappedPluginControl IWrappedPluginControl;

#endif 	/* __IWrappedPluginControl_FWD_DEFINED__ */


#ifndef __IUserInterface_FWD_DEFINED__
#define __IUserInterface_FWD_DEFINED__
typedef interface IUserInterface IUserInterface;

#endif 	/* __IUserInterface_FWD_DEFINED__ */


#ifndef __ILibrary_FWD_DEFINED__
#define __ILibrary_FWD_DEFINED__
typedef interface ILibrary ILibrary;

#endif 	/* __ILibrary_FWD_DEFINED__ */


#ifndef __ISettings_FWD_DEFINED__
#define __ISettings_FWD_DEFINED__
typedef interface ISettings ISettings;

#endif 	/* __ISettings_FWD_DEFINED__ */


#ifndef __ISMenu_FWD_DEFINED__
#define __ISMenu_FWD_DEFINED__
typedef interface ISMenu ISMenu;

#endif 	/* __ISMenu_FWD_DEFINED__ */


#ifndef __ISToolbarItem_FWD_DEFINED__
#define __ISToolbarItem_FWD_DEFINED__
typedef interface ISToolbarItem ISToolbarItem;

#endif 	/* __ISToolbarItem_FWD_DEFINED__ */


#ifndef __IGenericView_FWD_DEFINED__
#define __IGenericView_FWD_DEFINED__
typedef interface IGenericView IGenericView;

#endif 	/* __IGenericView_FWD_DEFINED__ */


#ifndef __IEnvyFile_FWD_DEFINED__
#define __IEnvyFile_FWD_DEFINED__
typedef interface IEnvyFile IEnvyFile;

#endif 	/* __IEnvyFile_FWD_DEFINED__ */


#ifndef __ILibraryFile_FWD_DEFINED__
#define __ILibraryFile_FWD_DEFINED__
typedef interface ILibraryFile ILibraryFile;

#endif 	/* __ILibraryFile_FWD_DEFINED__ */


#ifndef __ILibraryFiles_FWD_DEFINED__
#define __ILibraryFiles_FWD_DEFINED__
typedef interface ILibraryFiles ILibraryFiles;

#endif 	/* __ILibraryFiles_FWD_DEFINED__ */


#ifndef __ILibraryFolder_FWD_DEFINED__
#define __ILibraryFolder_FWD_DEFINED__
typedef interface ILibraryFolder ILibraryFolder;

#endif 	/* __ILibraryFolder_FWD_DEFINED__ */


#ifndef __ILibraryFolders_FWD_DEFINED__
#define __ILibraryFolders_FWD_DEFINED__
typedef interface ILibraryFolders ILibraryFolders;

#endif 	/* __ILibraryFolders_FWD_DEFINED__ */


#ifndef __ILibraryPlugin_FWD_DEFINED__
#define __ILibraryPlugin_FWD_DEFINED__
typedef interface ILibraryPlugin ILibraryPlugin;

#endif 	/* __ILibraryPlugin_FWD_DEFINED__ */


#ifndef __ICollectionHtmlView_FWD_DEFINED__
#define __ICollectionHtmlView_FWD_DEFINED__
typedef interface ICollectionHtmlView ICollectionHtmlView;

#endif 	/* __ICollectionHtmlView_FWD_DEFINED__ */


#ifndef __EnvyApplication_FWD_DEFINED__
#define __EnvyApplication_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyApplication EnvyApplication;
#else
typedef struct EnvyApplication EnvyApplication;
#endif /* __cplusplus */

#endif 	/* __EnvyApplication_FWD_DEFINED__ */


#ifndef __EnvyXML_FWD_DEFINED__
#define __EnvyXML_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyXML EnvyXML;
#else
typedef struct EnvyXML EnvyXML;
#endif /* __cplusplus */

#endif 	/* __EnvyXML_FWD_DEFINED__ */


#ifndef __EnvyXMLCollection_FWD_DEFINED__
#define __EnvyXMLCollection_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyXMLCollection EnvyXMLCollection;
#else
typedef struct EnvyXMLCollection EnvyXMLCollection;
#endif /* __cplusplus */

#endif 	/* __EnvyXMLCollection_FWD_DEFINED__ */


#ifndef __EnvyDataSource_FWD_DEFINED__
#define __EnvyDataSource_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyDataSource EnvyDataSource;
#else
typedef struct EnvyDataSource EnvyDataSource;
#endif /* __cplusplus */

#endif 	/* __EnvyDataSource_FWD_DEFINED__ */


#ifndef __EnvyIEProtocol_FWD_DEFINED__
#define __EnvyIEProtocol_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyIEProtocol EnvyIEProtocol;
#else
typedef struct EnvyIEProtocol EnvyIEProtocol;
#endif /* __cplusplus */

#endif 	/* __EnvyIEProtocol_FWD_DEFINED__ */


#ifndef __EnvyIEProtocolRequest_FWD_DEFINED__
#define __EnvyIEProtocolRequest_FWD_DEFINED__

#ifdef __cplusplus
typedef class EnvyIEProtocolRequest EnvyIEProtocolRequest;
#else
typedef struct EnvyIEProtocolRequest EnvyIEProtocolRequest;
#endif /* __cplusplus */

#endif 	/* __EnvyIEProtocolRequest_FWD_DEFINED__ */


/* header files for imported files */
#include "ShObjIdl.h"

#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __Envy_LIBRARY_DEFINED__
#define __Envy_LIBRARY_DEFINED__

/* library Envy */
/* [version][uuid] */ 


typedef /* [public][public][public][public][public][public][public][public][public][public][public] */ 
enum __MIDL___MIDL_itf_Envy_0000_0000_0001
    {
        TRI_UNKNOWN	= 0,
        TRI_FALSE	= 1,
        TRI_TRUE	= 2
    } 	TRISTATE;






typedef /* [public][public] */ 
enum __MIDL___MIDL_itf_Envy_0000_0000_0002
    {
        xmlNode	= 0,
        xmlElement	= ( xmlNode + 1 ) ,
        xmlAttribute	= ( xmlElement + 1 ) 
    } 	SXMLNodeType;


typedef /* [public][public][public][public][public] */ struct __MIDL___MIDL_itf_Envy_0001_0066_0001
    {
    int cbSize;
    int nFlags;
    int nWidth;
    int nHeight;
    int nComponents;
    int nQuality;
    } 	IMAGESERVICEDATA;

typedef /* [public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0066_0002
    {
        IMAGESERVICE_SCANONLY	= 0x1,
        IMAGESERVICE_PARTIAL_IN	= 0x2,
        IMAGESERVICE_PARTIAL_OUT	= 0x4
    } 	IMAGESERVICEFLAGS;


typedef /* [public][public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0070_0001
    {
        smsNull	= 0,
        smsOpen	= ( smsNull + 1 ) ,
        smsPaused	= ( smsOpen + 1 ) ,
        smsPlaying	= ( smsPaused + 1 ) 
    } 	MediaState;

typedef /* [public][public][public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0070_0002
    {
        smaDefault	= 1,
        smzDistort	= -1,
        smzFill	= 0,
        smzOne	= 1,
        smzDouble	= 2,
        smzHalf	= 4
    } 	MediaZoom;

typedef /* [public][public] */ struct __MIDL___MIDL_itf_Envy_0001_0071_0001
    {
    DWORD nTime;
    BYTE nWaveform[ 2 ][ 512 ];
    BYTE nSpectrum[ 2 ][ 512 ];
    } 	MEDIAVISCHUNK;

#define MSG_SEVERITY_MASK		0x000f
#define MSG_ERROR				0x0000
#define MSG_WARNING				0x0001
#define MSG_NOTICE				0x0002
#define MSG_INFO					0x0003
#define MSG_DEBUG				0x0004
#define MSG_FACILITY_MASK		0xff00
#define MSG_FACILITY_DEFAULT		0x0000
#define MSG_FACILITY_SEARCH		0x0100
#define MSG_FACILITY_INCOMING	0x0200
#define MSG_FACILITY_OUTGOING	0x0300
#define MSG_TRAY					0x0010








typedef /* [public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0075_0001
    {
        guiWindowed	= 0,
        guiTabbed	= ( guiWindowed + 1 ) ,
        guiBasic	= ( guiTabbed + 1 ) 
    } 	GuiMode;

typedef /* [public][public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0076_0001
    {
        mnuMenu	= 0,
        mnuSeparator	= ( mnuMenu + 1 ) ,
        mnuCommand	= ( mnuSeparator + 1 ) 
    } 	SMenuType;

typedef /* [public][public] */ 
enum __MIDL___MIDL_itf_Envy_0001_0077_0001
    {
        tbSeparator	= 0,
        tbButton	= ( tbSeparator + 1 ) ,
        tbControl	= ( tbButton + 1 ) 
    } 	SToolbarType;






typedef 
enum tagURN_TYPE
    {
        URN_SHA1	= 0,
        URN_TIGER	= ( URN_SHA1 + 1 ) ,
        URN_ED2K	= ( URN_TIGER + 1 ) ,
        URN_MD5	= ( URN_ED2K + 1 ) ,
        URN_BTIH	= ( URN_MD5 + 1 ) 
    } 	URN_TYPE;

typedef 
enum tagENCODING
    {
        ENCODING_GUID	= 0,
        ENCODING_BASE16	= ( ENCODING_GUID + 1 ) ,
        ENCODING_BASE32	= ( ENCODING_BASE16 + 1 ) 
    } 	ENCODING;


EXTERN_C const IID LIBID_Envy;

#ifndef __IApplication_INTERFACE_DEFINED__
#define __IApplication_INTERFACE_DEFINED__

/* interface IApplication */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_IApplication;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8EBD0B6F-7BC4-44d1-BEC1-03E22DC2A587")
    IApplication : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Version( 
            /* [retval][out] */ BSTR *psVersion) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE CheckVersion( 
            /* [in] */ BSTR sVersion) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE CreateXML( 
            /* [retval][out] */ ISXMLElement **ppXML) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_UserInterface( 
            /* [retval][out] */ IUserInterface **ppUserInterface) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Settings( 
            /* [retval][out] */ ISettings **ppSettings) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ImageService( 
            /* [retval][out] */ IImageServicePlugin **ppImageService) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_SmartAgent( 
            /* [retval][out] */ BSTR *psSmartAgent) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Message( 
            /* [in] */ WORD nType,
            /* [in] */ BSTR bsMessage) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IApplicationVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IApplication * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IApplication * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IApplication * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IApplication * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IApplication * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IApplication * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IApplication * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(IApplication, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            IApplication * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(IApplication, get_Version)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Version )( 
            IApplication * This,
            /* [retval][out] */ BSTR *psVersion);
        
        DECLSPEC_XFGVIRT(IApplication, CheckVersion)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *CheckVersion )( 
            IApplication * This,
            /* [in] */ BSTR sVersion);
        
        DECLSPEC_XFGVIRT(IApplication, CreateXML)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *CreateXML )( 
            IApplication * This,
            /* [retval][out] */ ISXMLElement **ppXML);
        
        DECLSPEC_XFGVIRT(IApplication, get_UserInterface)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_UserInterface )( 
            IApplication * This,
            /* [retval][out] */ IUserInterface **ppUserInterface);
        
        DECLSPEC_XFGVIRT(IApplication, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            IApplication * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(IApplication, get_Settings)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Settings )( 
            IApplication * This,
            /* [retval][out] */ ISettings **ppSettings);
        
        DECLSPEC_XFGVIRT(IApplication, get_ImageService)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ImageService )( 
            IApplication * This,
            /* [retval][out] */ IImageServicePlugin **ppImageService);
        
        DECLSPEC_XFGVIRT(IApplication, get_SmartAgent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_SmartAgent )( 
            IApplication * This,
            /* [retval][out] */ BSTR *psSmartAgent);
        
        DECLSPEC_XFGVIRT(IApplication, Message)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Message )( 
            IApplication * This,
            /* [in] */ WORD nType,
            /* [in] */ BSTR bsMessage);
        
        END_INTERFACE
    } IApplicationVtbl;

    interface IApplication
    {
        CONST_VTBL struct IApplicationVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IApplication_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IApplication_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IApplication_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IApplication_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IApplication_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IApplication_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IApplication_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IApplication_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define IApplication_get_Version(This,psVersion)	\
    ( (This)->lpVtbl -> get_Version(This,psVersion) ) 

#define IApplication_CheckVersion(This,sVersion)	\
    ( (This)->lpVtbl -> CheckVersion(This,sVersion) ) 

#define IApplication_CreateXML(This,ppXML)	\
    ( (This)->lpVtbl -> CreateXML(This,ppXML) ) 

#define IApplication_get_UserInterface(This,ppUserInterface)	\
    ( (This)->lpVtbl -> get_UserInterface(This,ppUserInterface) ) 

#define IApplication_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define IApplication_get_Settings(This,ppSettings)	\
    ( (This)->lpVtbl -> get_Settings(This,ppSettings) ) 

#define IApplication_get_ImageService(This,ppImageService)	\
    ( (This)->lpVtbl -> get_ImageService(This,ppImageService) ) 

#define IApplication_get_SmartAgent(This,psSmartAgent)	\
    ( (This)->lpVtbl -> get_SmartAgent(This,psSmartAgent) ) 

#define IApplication_Message(This,nType,bsMessage)	\
    ( (This)->lpVtbl -> Message(This,nType,bsMessage) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IApplication_INTERFACE_DEFINED__ */


#ifndef __ISXMLNode_INTERFACE_DEFINED__
#define __ISXMLNode_INTERFACE_DEFINED__

/* interface ISXMLNode */
/* [oleautomation][dual][uuid][object] */ 


EXTERN_C const IID IID_ISXMLNode;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("A0F89545-DAD8-4441-9DF4-BCB106B12234")
    ISXMLNode : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Parent( 
            /* [retval][out] */ ISXMLElement **ppParent) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Type( 
            /* [retval][out] */ SXMLNodeType *pnType) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_AsNode( 
            /* [retval][out] */ ISXMLNode **ppNode) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_AsElement( 
            /* [retval][out] */ ISXMLNode **ppElement) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_AsAttribute( 
            /* [retval][out] */ ISXMLNode **ppAttribute) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Name( 
            /* [retval][out] */ BSTR *psName) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Name( 
            /* [in] */ BSTR sName) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Value( 
            /* [retval][out] */ BSTR *psValue) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Value( 
            /* [in] */ BSTR sValue) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Delete( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE IsNamed( 
            /* [in] */ BSTR sName,
            /* [retval][out] */ VARIANT_BOOL *pbResult) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISXMLNodeVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISXMLNode * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISXMLNode * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISXMLNode * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISXMLNode * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISXMLNode * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISXMLNode * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISXMLNode * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Parent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Parent )( 
            ISXMLNode * This,
            /* [retval][out] */ ISXMLElement **ppParent);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Type)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Type )( 
            ISXMLNode * This,
            /* [retval][out] */ SXMLNodeType *pnType);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsNode)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsNode )( 
            ISXMLNode * This,
            /* [retval][out] */ ISXMLNode **ppNode);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsElement)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsElement )( 
            ISXMLNode * This,
            /* [retval][out] */ ISXMLNode **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsAttribute)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsAttribute )( 
            ISXMLNode * This,
            /* [retval][out] */ ISXMLNode **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            ISXMLNode * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Name)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Name )( 
            ISXMLNode * This,
            /* [in] */ BSTR sName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Value)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Value )( 
            ISXMLNode * This,
            /* [retval][out] */ BSTR *psValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Value)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Value )( 
            ISXMLNode * This,
            /* [in] */ BSTR sValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, Delete)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Delete )( 
            ISXMLNode * This);
        
        DECLSPEC_XFGVIRT(ISXMLNode, IsNamed)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *IsNamed )( 
            ISXMLNode * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        END_INTERFACE
    } ISXMLNodeVtbl;

    interface ISXMLNode
    {
        CONST_VTBL struct ISXMLNodeVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISXMLNode_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISXMLNode_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISXMLNode_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISXMLNode_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISXMLNode_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISXMLNode_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISXMLNode_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISXMLNode_get_Parent(This,ppParent)	\
    ( (This)->lpVtbl -> get_Parent(This,ppParent) ) 

#define ISXMLNode_get_Type(This,pnType)	\
    ( (This)->lpVtbl -> get_Type(This,pnType) ) 

#define ISXMLNode_get_AsNode(This,ppNode)	\
    ( (This)->lpVtbl -> get_AsNode(This,ppNode) ) 

#define ISXMLNode_get_AsElement(This,ppElement)	\
    ( (This)->lpVtbl -> get_AsElement(This,ppElement) ) 

#define ISXMLNode_get_AsAttribute(This,ppAttribute)	\
    ( (This)->lpVtbl -> get_AsAttribute(This,ppAttribute) ) 

#define ISXMLNode_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define ISXMLNode_put_Name(This,sName)	\
    ( (This)->lpVtbl -> put_Name(This,sName) ) 

#define ISXMLNode_get_Value(This,psValue)	\
    ( (This)->lpVtbl -> get_Value(This,psValue) ) 

#define ISXMLNode_put_Value(This,sValue)	\
    ( (This)->lpVtbl -> put_Value(This,sValue) ) 

#define ISXMLNode_Delete(This)	\
    ( (This)->lpVtbl -> Delete(This) ) 

#define ISXMLNode_IsNamed(This,sName,pbResult)	\
    ( (This)->lpVtbl -> IsNamed(This,sName,pbResult) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISXMLNode_INTERFACE_DEFINED__ */


#ifndef __ISXMLElement_INTERFACE_DEFINED__
#define __ISXMLElement_INTERFACE_DEFINED__

/* interface ISXMLElement */
/* [oleautomation][dual][uuid][object] */ 


EXTERN_C const IID IID_ISXMLElement;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("5198A470-F9EE-49eb-948C-F8176610A8B2")
    ISXMLElement : public ISXMLNode
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Elements( 
            /* [retval][out] */ ISXMLElements **ppElements) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Attributes( 
            /* [retval][out] */ ISXMLAttributes **ppAttributes) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Detach( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Clone( 
            /* [retval][out] */ ISXMLElement **ppClone) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE ToString( 
            /* [retval][out] */ BSTR *psValue) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE ToStringEx( 
            /* [in] */ VARIANT_BOOL bHeader,
            /* [in] */ VARIANT_BOOL bNewlines,
            /* [retval][out] */ BSTR *psValue) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE FromString( 
            /* [in] */ BSTR sXML,
            /* [retval][out] */ ISXMLElement **ppElement) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE GetWords( 
            /* [retval][out] */ BSTR *psWords) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISXMLElementVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISXMLElement * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISXMLElement * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISXMLElement * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISXMLElement * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISXMLElement * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISXMLElement * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISXMLElement * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Parent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Parent )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLElement **ppParent);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Type)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Type )( 
            ISXMLElement * This,
            /* [retval][out] */ SXMLNodeType *pnType);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsNode)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsNode )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLNode **ppNode);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsElement)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsElement )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLNode **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsAttribute)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsAttribute )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLNode **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            ISXMLElement * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Name)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Name )( 
            ISXMLElement * This,
            /* [in] */ BSTR sName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Value)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Value )( 
            ISXMLElement * This,
            /* [retval][out] */ BSTR *psValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Value)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Value )( 
            ISXMLElement * This,
            /* [in] */ BSTR sValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, Delete)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Delete )( 
            ISXMLElement * This);
        
        DECLSPEC_XFGVIRT(ISXMLNode, IsNamed)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *IsNamed )( 
            ISXMLElement * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        DECLSPEC_XFGVIRT(ISXMLElement, get_Elements)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Elements )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLElements **ppElements);
        
        DECLSPEC_XFGVIRT(ISXMLElement, get_Attributes)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Attributes )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLAttributes **ppAttributes);
        
        DECLSPEC_XFGVIRT(ISXMLElement, Detach)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Detach )( 
            ISXMLElement * This);
        
        DECLSPEC_XFGVIRT(ISXMLElement, Clone)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Clone )( 
            ISXMLElement * This,
            /* [retval][out] */ ISXMLElement **ppClone);
        
        DECLSPEC_XFGVIRT(ISXMLElement, ToString)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *ToString )( 
            ISXMLElement * This,
            /* [retval][out] */ BSTR *psValue);
        
        DECLSPEC_XFGVIRT(ISXMLElement, ToStringEx)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *ToStringEx )( 
            ISXMLElement * This,
            /* [in] */ VARIANT_BOOL bHeader,
            /* [in] */ VARIANT_BOOL bNewlines,
            /* [retval][out] */ BSTR *psValue);
        
        DECLSPEC_XFGVIRT(ISXMLElement, FromString)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *FromString )( 
            ISXMLElement * This,
            /* [in] */ BSTR sXML,
            /* [retval][out] */ ISXMLElement **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLElement, GetWords)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *GetWords )( 
            ISXMLElement * This,
            /* [retval][out] */ BSTR *psWords);
        
        END_INTERFACE
    } ISXMLElementVtbl;

    interface ISXMLElement
    {
        CONST_VTBL struct ISXMLElementVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISXMLElement_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISXMLElement_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISXMLElement_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISXMLElement_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISXMLElement_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISXMLElement_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISXMLElement_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISXMLElement_get_Parent(This,ppParent)	\
    ( (This)->lpVtbl -> get_Parent(This,ppParent) ) 

#define ISXMLElement_get_Type(This,pnType)	\
    ( (This)->lpVtbl -> get_Type(This,pnType) ) 

#define ISXMLElement_get_AsNode(This,ppNode)	\
    ( (This)->lpVtbl -> get_AsNode(This,ppNode) ) 

#define ISXMLElement_get_AsElement(This,ppElement)	\
    ( (This)->lpVtbl -> get_AsElement(This,ppElement) ) 

#define ISXMLElement_get_AsAttribute(This,ppAttribute)	\
    ( (This)->lpVtbl -> get_AsAttribute(This,ppAttribute) ) 

#define ISXMLElement_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define ISXMLElement_put_Name(This,sName)	\
    ( (This)->lpVtbl -> put_Name(This,sName) ) 

#define ISXMLElement_get_Value(This,psValue)	\
    ( (This)->lpVtbl -> get_Value(This,psValue) ) 

#define ISXMLElement_put_Value(This,sValue)	\
    ( (This)->lpVtbl -> put_Value(This,sValue) ) 

#define ISXMLElement_Delete(This)	\
    ( (This)->lpVtbl -> Delete(This) ) 

#define ISXMLElement_IsNamed(This,sName,pbResult)	\
    ( (This)->lpVtbl -> IsNamed(This,sName,pbResult) ) 


#define ISXMLElement_get_Elements(This,ppElements)	\
    ( (This)->lpVtbl -> get_Elements(This,ppElements) ) 

#define ISXMLElement_get_Attributes(This,ppAttributes)	\
    ( (This)->lpVtbl -> get_Attributes(This,ppAttributes) ) 

#define ISXMLElement_Detach(This)	\
    ( (This)->lpVtbl -> Detach(This) ) 

#define ISXMLElement_Clone(This,ppClone)	\
    ( (This)->lpVtbl -> Clone(This,ppClone) ) 

#define ISXMLElement_ToString(This,psValue)	\
    ( (This)->lpVtbl -> ToString(This,psValue) ) 

#define ISXMLElement_ToStringEx(This,bHeader,bNewlines,psValue)	\
    ( (This)->lpVtbl -> ToStringEx(This,bHeader,bNewlines,psValue) ) 

#define ISXMLElement_FromString(This,sXML,ppElement)	\
    ( (This)->lpVtbl -> FromString(This,sXML,ppElement) ) 

#define ISXMLElement_GetWords(This,psWords)	\
    ( (This)->lpVtbl -> GetWords(This,psWords) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISXMLElement_INTERFACE_DEFINED__ */


#ifndef __ISXMLElements_INTERFACE_DEFINED__
#define __ISXMLElements_INTERFACE_DEFINED__

/* interface ISXMLElements */
/* [oleautomation][dual][uuid][object] */ 


EXTERN_C const IID IID_ISXMLElements;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("10BF271C-85A3-4ad4-8930-CC0E3CEEADA4")
    ISXMLElements : public IDispatch
    {
    public:
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISXMLElement **ppElement) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Create( 
            /* [in] */ BSTR strName,
            /* [retval][out] */ ISXMLElement **ppElement) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Attach( 
            /* [in] */ ISXMLElement *pElement) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE RemoveAll( void) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_First( 
            /* [retval][out] */ ISXMLElement **ppElement) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ByName( 
            /* [in] */ BSTR sName,
            /* [retval][out] */ ISXMLElement **ppElement) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISXMLElementsVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISXMLElements * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISXMLElements * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISXMLElements * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISXMLElements * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISXMLElements * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISXMLElements * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISXMLElements * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISXMLElements, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ISXMLElements * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ISXMLElements, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ISXMLElements * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISXMLElement **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLElements, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ISXMLElements * This,
            /* [retval][out] */ LONG *pnCount);
        
        DECLSPEC_XFGVIRT(ISXMLElements, Create)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Create )( 
            ISXMLElements * This,
            /* [in] */ BSTR strName,
            /* [retval][out] */ ISXMLElement **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLElements, Attach)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Attach )( 
            ISXMLElements * This,
            /* [in] */ ISXMLElement *pElement);
        
        DECLSPEC_XFGVIRT(ISXMLElements, RemoveAll)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *RemoveAll )( 
            ISXMLElements * This);
        
        DECLSPEC_XFGVIRT(ISXMLElements, get_First)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_First )( 
            ISXMLElements * This,
            /* [retval][out] */ ISXMLElement **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLElements, get_ByName)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ByName )( 
            ISXMLElements * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ ISXMLElement **ppElement);
        
        END_INTERFACE
    } ISXMLElementsVtbl;

    interface ISXMLElements
    {
        CONST_VTBL struct ISXMLElementsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISXMLElements_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISXMLElements_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISXMLElements_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISXMLElements_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISXMLElements_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISXMLElements_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISXMLElements_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISXMLElements_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ISXMLElements_get_Item(This,vIndex,ppElement)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppElement) ) 

#define ISXMLElements_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#define ISXMLElements_Create(This,strName,ppElement)	\
    ( (This)->lpVtbl -> Create(This,strName,ppElement) ) 

#define ISXMLElements_Attach(This,pElement)	\
    ( (This)->lpVtbl -> Attach(This,pElement) ) 

#define ISXMLElements_RemoveAll(This)	\
    ( (This)->lpVtbl -> RemoveAll(This) ) 

#define ISXMLElements_get_First(This,ppElement)	\
    ( (This)->lpVtbl -> get_First(This,ppElement) ) 

#define ISXMLElements_get_ByName(This,sName,ppElement)	\
    ( (This)->lpVtbl -> get_ByName(This,sName,ppElement) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISXMLElements_INTERFACE_DEFINED__ */


#ifndef __ISXMLAttribute_INTERFACE_DEFINED__
#define __ISXMLAttribute_INTERFACE_DEFINED__

/* interface ISXMLAttribute */
/* [oleautomation][dual][uuid][object] */ 


EXTERN_C const IID IID_ISXMLAttribute;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("6D4598A7-26A1-4990-BA60-DE0E212AF93C")
    ISXMLAttribute : public ISXMLNode
    {
    public:
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Detach( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Clone( 
            /* [retval][out] */ ISXMLAttribute **ppClone) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISXMLAttributeVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISXMLAttribute * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISXMLAttribute * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISXMLAttribute * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISXMLAttribute * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISXMLAttribute * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISXMLAttribute * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISXMLAttribute * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Parent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Parent )( 
            ISXMLAttribute * This,
            /* [retval][out] */ ISXMLElement **ppParent);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Type)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Type )( 
            ISXMLAttribute * This,
            /* [retval][out] */ SXMLNodeType *pnType);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsNode)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsNode )( 
            ISXMLAttribute * This,
            /* [retval][out] */ ISXMLNode **ppNode);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsElement)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsElement )( 
            ISXMLAttribute * This,
            /* [retval][out] */ ISXMLNode **ppElement);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_AsAttribute)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_AsAttribute )( 
            ISXMLAttribute * This,
            /* [retval][out] */ ISXMLNode **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            ISXMLAttribute * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Name)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Name )( 
            ISXMLAttribute * This,
            /* [in] */ BSTR sName);
        
        DECLSPEC_XFGVIRT(ISXMLNode, get_Value)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Value )( 
            ISXMLAttribute * This,
            /* [retval][out] */ BSTR *psValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, put_Value)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Value )( 
            ISXMLAttribute * This,
            /* [in] */ BSTR sValue);
        
        DECLSPEC_XFGVIRT(ISXMLNode, Delete)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Delete )( 
            ISXMLAttribute * This);
        
        DECLSPEC_XFGVIRT(ISXMLNode, IsNamed)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *IsNamed )( 
            ISXMLAttribute * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        DECLSPEC_XFGVIRT(ISXMLAttribute, Detach)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Detach )( 
            ISXMLAttribute * This);
        
        DECLSPEC_XFGVIRT(ISXMLAttribute, Clone)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Clone )( 
            ISXMLAttribute * This,
            /* [retval][out] */ ISXMLAttribute **ppClone);
        
        END_INTERFACE
    } ISXMLAttributeVtbl;

    interface ISXMLAttribute
    {
        CONST_VTBL struct ISXMLAttributeVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISXMLAttribute_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISXMLAttribute_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISXMLAttribute_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISXMLAttribute_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISXMLAttribute_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISXMLAttribute_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISXMLAttribute_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISXMLAttribute_get_Parent(This,ppParent)	\
    ( (This)->lpVtbl -> get_Parent(This,ppParent) ) 

#define ISXMLAttribute_get_Type(This,pnType)	\
    ( (This)->lpVtbl -> get_Type(This,pnType) ) 

#define ISXMLAttribute_get_AsNode(This,ppNode)	\
    ( (This)->lpVtbl -> get_AsNode(This,ppNode) ) 

#define ISXMLAttribute_get_AsElement(This,ppElement)	\
    ( (This)->lpVtbl -> get_AsElement(This,ppElement) ) 

#define ISXMLAttribute_get_AsAttribute(This,ppAttribute)	\
    ( (This)->lpVtbl -> get_AsAttribute(This,ppAttribute) ) 

#define ISXMLAttribute_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define ISXMLAttribute_put_Name(This,sName)	\
    ( (This)->lpVtbl -> put_Name(This,sName) ) 

#define ISXMLAttribute_get_Value(This,psValue)	\
    ( (This)->lpVtbl -> get_Value(This,psValue) ) 

#define ISXMLAttribute_put_Value(This,sValue)	\
    ( (This)->lpVtbl -> put_Value(This,sValue) ) 

#define ISXMLAttribute_Delete(This)	\
    ( (This)->lpVtbl -> Delete(This) ) 

#define ISXMLAttribute_IsNamed(This,sName,pbResult)	\
    ( (This)->lpVtbl -> IsNamed(This,sName,pbResult) ) 


#define ISXMLAttribute_Detach(This)	\
    ( (This)->lpVtbl -> Detach(This) ) 

#define ISXMLAttribute_Clone(This,ppClone)	\
    ( (This)->lpVtbl -> Clone(This,ppClone) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISXMLAttribute_INTERFACE_DEFINED__ */


#ifndef __ISXMLAttributes_INTERFACE_DEFINED__
#define __ISXMLAttributes_INTERFACE_DEFINED__

/* interface ISXMLAttributes */
/* [oleautomation][dual][uuid][object] */ 


EXTERN_C const IID IID_ISXMLAttributes;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8E03E1BF-CCC0-4616-9C0D-8204A83BAEB4")
    ISXMLAttributes : public IDispatch
    {
    public:
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISXMLAttribute **ppAttribute) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Add( 
            /* [in] */ BSTR strName,
            /* [in] */ BSTR strValue) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Create( 
            /* [in] */ BSTR strName,
            /* [retval][out] */ ISXMLAttribute **ppAttribute) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Attach( 
            /* [in] */ ISXMLAttribute *pAttribute) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE RemoveAll( void) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ByName( 
            /* [in] */ BSTR sName,
            /* [retval][out] */ ISXMLAttribute **ppAttribute) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Get( 
            /* [in] */ BSTR sName,
            /* [retval][out] */ BSTR *psValue) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISXMLAttributesVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISXMLAttributes * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISXMLAttributes * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISXMLAttributes * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISXMLAttributes * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISXMLAttributes * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISXMLAttributes * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISXMLAttributes * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ISXMLAttributes * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ISXMLAttributes * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISXMLAttribute **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ISXMLAttributes * This,
            /* [retval][out] */ LONG *pnCount);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, Add)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Add )( 
            ISXMLAttributes * This,
            /* [in] */ BSTR strName,
            /* [in] */ BSTR strValue);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, Create)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Create )( 
            ISXMLAttributes * This,
            /* [in] */ BSTR strName,
            /* [retval][out] */ ISXMLAttribute **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, Attach)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Attach )( 
            ISXMLAttributes * This,
            /* [in] */ ISXMLAttribute *pAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, RemoveAll)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *RemoveAll )( 
            ISXMLAttributes * This);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, get_ByName)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ByName )( 
            ISXMLAttributes * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ ISXMLAttribute **ppAttribute);
        
        DECLSPEC_XFGVIRT(ISXMLAttributes, get_Get)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Get )( 
            ISXMLAttributes * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ BSTR *psValue);
        
        END_INTERFACE
    } ISXMLAttributesVtbl;

    interface ISXMLAttributes
    {
        CONST_VTBL struct ISXMLAttributesVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISXMLAttributes_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISXMLAttributes_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISXMLAttributes_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISXMLAttributes_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISXMLAttributes_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISXMLAttributes_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISXMLAttributes_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISXMLAttributes_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ISXMLAttributes_get_Item(This,vIndex,ppAttribute)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppAttribute) ) 

#define ISXMLAttributes_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#define ISXMLAttributes_Add(This,strName,strValue)	\
    ( (This)->lpVtbl -> Add(This,strName,strValue) ) 

#define ISXMLAttributes_Create(This,strName,ppAttribute)	\
    ( (This)->lpVtbl -> Create(This,strName,ppAttribute) ) 

#define ISXMLAttributes_Attach(This,pAttribute)	\
    ( (This)->lpVtbl -> Attach(This,pAttribute) ) 

#define ISXMLAttributes_RemoveAll(This)	\
    ( (This)->lpVtbl -> RemoveAll(This) ) 

#define ISXMLAttributes_get_ByName(This,sName,ppAttribute)	\
    ( (This)->lpVtbl -> get_ByName(This,sName,ppAttribute) ) 

#define ISXMLAttributes_get_Get(This,sName,psValue)	\
    ( (This)->lpVtbl -> get_Get(This,sName,psValue) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISXMLAttributes_INTERFACE_DEFINED__ */


#ifndef __IGeneralPlugin_INTERFACE_DEFINED__
#define __IGeneralPlugin_INTERFACE_DEFINED__

/* interface IGeneralPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IGeneralPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("D1B5D3A4-B890-470a-A3FF-9700F3C2A063")
    IGeneralPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetApplication( 
            /* [in] */ IApplication *pApplication) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE QueryCapabilities( 
            /* [out] */ DWORD *pnCaps) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Configure( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnSkinChanged( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IGeneralPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGeneralPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGeneralPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGeneralPlugin * This);
        
        DECLSPEC_XFGVIRT(IGeneralPlugin, SetApplication)
        HRESULT ( STDMETHODCALLTYPE *SetApplication )( 
            IGeneralPlugin * This,
            /* [in] */ IApplication *pApplication);
        
        DECLSPEC_XFGVIRT(IGeneralPlugin, QueryCapabilities)
        HRESULT ( STDMETHODCALLTYPE *QueryCapabilities )( 
            IGeneralPlugin * This,
            /* [out] */ DWORD *pnCaps);
        
        DECLSPEC_XFGVIRT(IGeneralPlugin, Configure)
        HRESULT ( STDMETHODCALLTYPE *Configure )( 
            IGeneralPlugin * This);
        
        DECLSPEC_XFGVIRT(IGeneralPlugin, OnSkinChanged)
        HRESULT ( STDMETHODCALLTYPE *OnSkinChanged )( 
            IGeneralPlugin * This);
        
        END_INTERFACE
    } IGeneralPluginVtbl;

    interface IGeneralPlugin
    {
        CONST_VTBL struct IGeneralPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IGeneralPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IGeneralPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IGeneralPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IGeneralPlugin_SetApplication(This,pApplication)	\
    ( (This)->lpVtbl -> SetApplication(This,pApplication) ) 

#define IGeneralPlugin_QueryCapabilities(This,pnCaps)	\
    ( (This)->lpVtbl -> QueryCapabilities(This,pnCaps) ) 

#define IGeneralPlugin_Configure(This)	\
    ( (This)->lpVtbl -> Configure(This) ) 

#define IGeneralPlugin_OnSkinChanged(This)	\
    ( (This)->lpVtbl -> OnSkinChanged(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IGeneralPlugin_INTERFACE_DEFINED__ */


#ifndef __ICommandPlugin_INTERFACE_DEFINED__
#define __ICommandPlugin_INTERFACE_DEFINED__

/* interface ICommandPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_ICommandPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("CB25DAED-D745-45db-994E-32639D2888A9")
    ICommandPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE RegisterCommands( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE InsertCommands( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnUpdate( 
            /* [in] */ UINT nCommandID,
            /* [out][in] */ TRISTATE *pbVisible,
            /* [out][in] */ TRISTATE *pbEnabled,
            /* [out][in] */ TRISTATE *pbChecked) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnCommand( 
            /* [in] */ UINT nCommandID) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ICommandPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICommandPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICommandPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICommandPlugin * This);
        
        DECLSPEC_XFGVIRT(ICommandPlugin, RegisterCommands)
        HRESULT ( STDMETHODCALLTYPE *RegisterCommands )( 
            ICommandPlugin * This);
        
        DECLSPEC_XFGVIRT(ICommandPlugin, InsertCommands)
        HRESULT ( STDMETHODCALLTYPE *InsertCommands )( 
            ICommandPlugin * This);
        
        DECLSPEC_XFGVIRT(ICommandPlugin, OnUpdate)
        HRESULT ( STDMETHODCALLTYPE *OnUpdate )( 
            ICommandPlugin * This,
            /* [in] */ UINT nCommandID,
            /* [out][in] */ TRISTATE *pbVisible,
            /* [out][in] */ TRISTATE *pbEnabled,
            /* [out][in] */ TRISTATE *pbChecked);
        
        DECLSPEC_XFGVIRT(ICommandPlugin, OnCommand)
        HRESULT ( STDMETHODCALLTYPE *OnCommand )( 
            ICommandPlugin * This,
            /* [in] */ UINT nCommandID);
        
        END_INTERFACE
    } ICommandPluginVtbl;

    interface ICommandPlugin
    {
        CONST_VTBL struct ICommandPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ICommandPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ICommandPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ICommandPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ICommandPlugin_RegisterCommands(This)	\
    ( (This)->lpVtbl -> RegisterCommands(This) ) 

#define ICommandPlugin_InsertCommands(This)	\
    ( (This)->lpVtbl -> InsertCommands(This) ) 

#define ICommandPlugin_OnUpdate(This,nCommandID,pbVisible,pbEnabled,pbChecked)	\
    ( (This)->lpVtbl -> OnUpdate(This,nCommandID,pbVisible,pbEnabled,pbChecked) ) 

#define ICommandPlugin_OnCommand(This,nCommandID)	\
    ( (This)->lpVtbl -> OnCommand(This,nCommandID) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ICommandPlugin_INTERFACE_DEFINED__ */


#ifndef __IExecutePlugin_INTERFACE_DEFINED__
#define __IExecutePlugin_INTERFACE_DEFINED__

/* interface IExecutePlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IExecutePlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8E878640-37B5-44a3-A37C-FC3BF1CCF6B6")
    IExecutePlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE OnExecute( 
            /* [in] */ BSTR sFilePath) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnEnqueue( 
            /* [in] */ BSTR sFilePath) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IExecutePluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IExecutePlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IExecutePlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IExecutePlugin * This);
        
        DECLSPEC_XFGVIRT(IExecutePlugin, OnExecute)
        HRESULT ( STDMETHODCALLTYPE *OnExecute )( 
            IExecutePlugin * This,
            /* [in] */ BSTR sFilePath);
        
        DECLSPEC_XFGVIRT(IExecutePlugin, OnEnqueue)
        HRESULT ( STDMETHODCALLTYPE *OnEnqueue )( 
            IExecutePlugin * This,
            /* [in] */ BSTR sFilePath);
        
        END_INTERFACE
    } IExecutePluginVtbl;

    interface IExecutePlugin
    {
        CONST_VTBL struct IExecutePluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IExecutePlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IExecutePlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IExecutePlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IExecutePlugin_OnExecute(This,sFilePath)	\
    ( (This)->lpVtbl -> OnExecute(This,sFilePath) ) 

#define IExecutePlugin_OnEnqueue(This,sFilePath)	\
    ( (This)->lpVtbl -> OnEnqueue(This,sFilePath) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IExecutePlugin_INTERFACE_DEFINED__ */


#ifndef __IChatPlugin_INTERFACE_DEFINED__
#define __IChatPlugin_INTERFACE_DEFINED__

/* interface IChatPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IChatPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8065EF37-F0EA-4898-BBBD-D37798DE83CB")
    IChatPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE OnChatMessage( 
            /* [in] */ BSTR sChatID,
            /* [in] */ VARIANT_BOOL bOutgoing,
            /* [in] */ BSTR sFrom,
            /* [in] */ BSTR sTo,
            /* [in] */ BSTR sMessage) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IChatPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IChatPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IChatPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IChatPlugin * This);
        
        DECLSPEC_XFGVIRT(IChatPlugin, OnChatMessage)
        HRESULT ( STDMETHODCALLTYPE *OnChatMessage )( 
            IChatPlugin * This,
            /* [in] */ BSTR sChatID,
            /* [in] */ VARIANT_BOOL bOutgoing,
            /* [in] */ BSTR sFrom,
            /* [in] */ BSTR sTo,
            /* [in] */ BSTR sMessage);
        
        END_INTERFACE
    } IChatPluginVtbl;

    interface IChatPlugin
    {
        CONST_VTBL struct IChatPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IChatPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IChatPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IChatPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IChatPlugin_OnChatMessage(This,sChatID,bOutgoing,sFrom,sTo,sMessage)	\
    ( (This)->lpVtbl -> OnChatMessage(This,sChatID,bOutgoing,sFrom,sTo,sMessage) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IChatPlugin_INTERFACE_DEFINED__ */


#ifndef __ISToolbar_INTERFACE_DEFINED__
#define __ISToolbar_INTERFACE_DEFINED__

/* interface ISToolbar */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ISToolbar;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("E02F505E-9649-4eb1-AB3F-56FFDFF5B92C")
    ISToolbar : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_UserInterface( 
            /* [retval][out] */ IUserInterface **ppUserInterface) = 0;
        
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISToolbarItem **ppItem) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE InsertSeparator( 
            /* [in] */ LONG nPosition) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE InsertButton( 
            /* [in] */ LONG nPosition,
            /* [in] */ LONG nCommandID,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISToolbarItem **ppItem) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISToolbarVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISToolbar * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISToolbar * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISToolbar * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISToolbar * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISToolbar * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISToolbar * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISToolbar * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISToolbar, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ISToolbar * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ISToolbar, get_UserInterface)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_UserInterface )( 
            ISToolbar * This,
            /* [retval][out] */ IUserInterface **ppUserInterface);
        
        DECLSPEC_XFGVIRT(ISToolbar, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ISToolbar * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ISToolbar, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ISToolbar * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISToolbarItem **ppItem);
        
        DECLSPEC_XFGVIRT(ISToolbar, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ISToolbar * This,
            /* [retval][out] */ LONG *pnCount);
        
        DECLSPEC_XFGVIRT(ISToolbar, InsertSeparator)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *InsertSeparator )( 
            ISToolbar * This,
            /* [in] */ LONG nPosition);
        
        DECLSPEC_XFGVIRT(ISToolbar, InsertButton)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *InsertButton )( 
            ISToolbar * This,
            /* [in] */ LONG nPosition,
            /* [in] */ LONG nCommandID,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISToolbarItem **ppItem);
        
        END_INTERFACE
    } ISToolbarVtbl;

    interface ISToolbar
    {
        CONST_VTBL struct ISToolbarVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISToolbar_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISToolbar_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISToolbar_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISToolbar_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISToolbar_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISToolbar_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISToolbar_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISToolbar_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ISToolbar_get_UserInterface(This,ppUserInterface)	\
    ( (This)->lpVtbl -> get_UserInterface(This,ppUserInterface) ) 

#define ISToolbar_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ISToolbar_get_Item(This,vIndex,ppItem)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppItem) ) 

#define ISToolbar_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#define ISToolbar_InsertSeparator(This,nPosition)	\
    ( (This)->lpVtbl -> InsertSeparator(This,nPosition) ) 

#define ISToolbar_InsertButton(This,nPosition,nCommandID,sText,ppItem)	\
    ( (This)->lpVtbl -> InsertButton(This,nPosition,nCommandID,sText,ppItem) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISToolbar_INTERFACE_DEFINED__ */


#ifndef __IPluginWindow_INTERFACE_DEFINED__
#define __IPluginWindow_INTERFACE_DEFINED__

/* interface IPluginWindow */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IPluginWindow;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("ADDB77AE-3483-4a15-B391-AE31563BD7E3")
    IPluginWindow : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE ListenForSingleMessage( 
            /* [in] */ UINT nMessage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ListenForMultipleMessages( 
            /* [in] */ SAFEARRAY * pMessages) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Create1( 
            /* [in] */ BSTR bsCaption,
            /* [in] */ HICON hIcon,
            /* [in] */ VARIANT_BOOL bPanel,
            /* [in] */ VARIANT_BOOL bTabbed) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Create2( 
            /* [in] */ UINT nCommandID,
            /* [in] */ VARIANT_BOOL bPanel,
            /* [in] */ VARIANT_BOOL bTabbed) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetHwnd( 
            /* [out] */ HWND *phWnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE HandleMessage( 
            /* [out] */ LRESULT *plResult) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE LoadState( 
            /* [in] */ VARIANT_BOOL bMaximise) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SaveState( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ThrowMenu( 
            /* [in] */ BSTR sName,
            /* [in] */ LONG nDefaultID,
            /* [in] */ POINT *pPoint) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AddToolbar( 
            /* [in] */ BSTR sName,
            /* [in] */ LONG nPosition,
            /* [out] */ HWND *phWnd,
            /* [retval][out] */ ISToolbar **ppToolbar) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AdjustWindowRect( 
            /* [out][in] */ RECT *pRect,
            /* [in] */ VARIANT_BOOL bClientToWindow) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IPluginWindowVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IPluginWindow * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IPluginWindow * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IPluginWindow * This);
        
        DECLSPEC_XFGVIRT(IPluginWindow, ListenForSingleMessage)
        HRESULT ( STDMETHODCALLTYPE *ListenForSingleMessage )( 
            IPluginWindow * This,
            /* [in] */ UINT nMessage);
        
        DECLSPEC_XFGVIRT(IPluginWindow, ListenForMultipleMessages)
        HRESULT ( STDMETHODCALLTYPE *ListenForMultipleMessages )( 
            IPluginWindow * This,
            /* [in] */ SAFEARRAY * pMessages);
        
        DECLSPEC_XFGVIRT(IPluginWindow, Create1)
        HRESULT ( STDMETHODCALLTYPE *Create1 )( 
            IPluginWindow * This,
            /* [in] */ BSTR bsCaption,
            /* [in] */ HICON hIcon,
            /* [in] */ VARIANT_BOOL bPanel,
            /* [in] */ VARIANT_BOOL bTabbed);
        
        DECLSPEC_XFGVIRT(IPluginWindow, Create2)
        HRESULT ( STDMETHODCALLTYPE *Create2 )( 
            IPluginWindow * This,
            /* [in] */ UINT nCommandID,
            /* [in] */ VARIANT_BOOL bPanel,
            /* [in] */ VARIANT_BOOL bTabbed);
        
        DECLSPEC_XFGVIRT(IPluginWindow, GetHwnd)
        HRESULT ( STDMETHODCALLTYPE *GetHwnd )( 
            IPluginWindow * This,
            /* [out] */ HWND *phWnd);
        
        DECLSPEC_XFGVIRT(IPluginWindow, HandleMessage)
        HRESULT ( STDMETHODCALLTYPE *HandleMessage )( 
            IPluginWindow * This,
            /* [out] */ LRESULT *plResult);
        
        DECLSPEC_XFGVIRT(IPluginWindow, LoadState)
        HRESULT ( STDMETHODCALLTYPE *LoadState )( 
            IPluginWindow * This,
            /* [in] */ VARIANT_BOOL bMaximise);
        
        DECLSPEC_XFGVIRT(IPluginWindow, SaveState)
        HRESULT ( STDMETHODCALLTYPE *SaveState )( 
            IPluginWindow * This);
        
        DECLSPEC_XFGVIRT(IPluginWindow, ThrowMenu)
        HRESULT ( STDMETHODCALLTYPE *ThrowMenu )( 
            IPluginWindow * This,
            /* [in] */ BSTR sName,
            /* [in] */ LONG nDefaultID,
            /* [in] */ POINT *pPoint);
        
        DECLSPEC_XFGVIRT(IPluginWindow, AddToolbar)
        HRESULT ( STDMETHODCALLTYPE *AddToolbar )( 
            IPluginWindow * This,
            /* [in] */ BSTR sName,
            /* [in] */ LONG nPosition,
            /* [out] */ HWND *phWnd,
            /* [retval][out] */ ISToolbar **ppToolbar);
        
        DECLSPEC_XFGVIRT(IPluginWindow, AdjustWindowRect)
        HRESULT ( STDMETHODCALLTYPE *AdjustWindowRect )( 
            IPluginWindow * This,
            /* [out][in] */ RECT *pRect,
            /* [in] */ VARIANT_BOOL bClientToWindow);
        
        END_INTERFACE
    } IPluginWindowVtbl;

    interface IPluginWindow
    {
        CONST_VTBL struct IPluginWindowVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IPluginWindow_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IPluginWindow_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IPluginWindow_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IPluginWindow_ListenForSingleMessage(This,nMessage)	\
    ( (This)->lpVtbl -> ListenForSingleMessage(This,nMessage) ) 

#define IPluginWindow_ListenForMultipleMessages(This,pMessages)	\
    ( (This)->lpVtbl -> ListenForMultipleMessages(This,pMessages) ) 

#define IPluginWindow_Create1(This,bsCaption,hIcon,bPanel,bTabbed)	\
    ( (This)->lpVtbl -> Create1(This,bsCaption,hIcon,bPanel,bTabbed) ) 

#define IPluginWindow_Create2(This,nCommandID,bPanel,bTabbed)	\
    ( (This)->lpVtbl -> Create2(This,nCommandID,bPanel,bTabbed) ) 

#define IPluginWindow_GetHwnd(This,phWnd)	\
    ( (This)->lpVtbl -> GetHwnd(This,phWnd) ) 

#define IPluginWindow_HandleMessage(This,plResult)	\
    ( (This)->lpVtbl -> HandleMessage(This,plResult) ) 

#define IPluginWindow_LoadState(This,bMaximise)	\
    ( (This)->lpVtbl -> LoadState(This,bMaximise) ) 

#define IPluginWindow_SaveState(This)	\
    ( (This)->lpVtbl -> SaveState(This) ) 

#define IPluginWindow_ThrowMenu(This,sName,nDefaultID,pPoint)	\
    ( (This)->lpVtbl -> ThrowMenu(This,sName,nDefaultID,pPoint) ) 

#define IPluginWindow_AddToolbar(This,sName,nPosition,phWnd,ppToolbar)	\
    ( (This)->lpVtbl -> AddToolbar(This,sName,nPosition,phWnd,ppToolbar) ) 

#define IPluginWindow_AdjustWindowRect(This,pRect,bClientToWindow)	\
    ( (This)->lpVtbl -> AdjustWindowRect(This,pRect,bClientToWindow) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IPluginWindow_INTERFACE_DEFINED__ */


#ifndef __IPluginWindowOwner_INTERFACE_DEFINED__
#define __IPluginWindowOwner_INTERFACE_DEFINED__

/* interface IPluginWindowOwner */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IPluginWindowOwner;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("C6631461-2654-4572-BB3C-54F52F0FF1B9")
    IPluginWindowOwner : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE OnTranslate( 
            /* [in] */ MSG *pMessage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnMessage( 
            /* [in] */ UINT nMessage,
            /* [in] */ WPARAM wParam,
            /* [in] */ LPARAM lParam,
            /* [out] */ LRESULT *plResult) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnUpdate( 
            /* [in] */ UINT nCommandID,
            /* [out][in] */ TRISTATE *pbVisible,
            /* [out][in] */ TRISTATE *pbEnabled,
            /* [out][in] */ TRISTATE *pbChecked) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnCommand( 
            /* [in] */ UINT nCommandID) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IPluginWindowOwnerVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IPluginWindowOwner * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IPluginWindowOwner * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IPluginWindowOwner * This);
        
        DECLSPEC_XFGVIRT(IPluginWindowOwner, OnTranslate)
        HRESULT ( STDMETHODCALLTYPE *OnTranslate )( 
            IPluginWindowOwner * This,
            /* [in] */ MSG *pMessage);
        
        DECLSPEC_XFGVIRT(IPluginWindowOwner, OnMessage)
        HRESULT ( STDMETHODCALLTYPE *OnMessage )( 
            IPluginWindowOwner * This,
            /* [in] */ UINT nMessage,
            /* [in] */ WPARAM wParam,
            /* [in] */ LPARAM lParam,
            /* [out] */ LRESULT *plResult);
        
        DECLSPEC_XFGVIRT(IPluginWindowOwner, OnUpdate)
        HRESULT ( STDMETHODCALLTYPE *OnUpdate )( 
            IPluginWindowOwner * This,
            /* [in] */ UINT nCommandID,
            /* [out][in] */ TRISTATE *pbVisible,
            /* [out][in] */ TRISTATE *pbEnabled,
            /* [out][in] */ TRISTATE *pbChecked);
        
        DECLSPEC_XFGVIRT(IPluginWindowOwner, OnCommand)
        HRESULT ( STDMETHODCALLTYPE *OnCommand )( 
            IPluginWindowOwner * This,
            /* [in] */ UINT nCommandID);
        
        END_INTERFACE
    } IPluginWindowOwnerVtbl;

    interface IPluginWindowOwner
    {
        CONST_VTBL struct IPluginWindowOwnerVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IPluginWindowOwner_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IPluginWindowOwner_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IPluginWindowOwner_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IPluginWindowOwner_OnTranslate(This,pMessage)	\
    ( (This)->lpVtbl -> OnTranslate(This,pMessage) ) 

#define IPluginWindowOwner_OnMessage(This,nMessage,wParam,lParam,plResult)	\
    ( (This)->lpVtbl -> OnMessage(This,nMessage,wParam,lParam,plResult) ) 

#define IPluginWindowOwner_OnUpdate(This,nCommandID,pbVisible,pbEnabled,pbChecked)	\
    ( (This)->lpVtbl -> OnUpdate(This,nCommandID,pbVisible,pbEnabled,pbChecked) ) 

#define IPluginWindowOwner_OnCommand(This,nCommandID)	\
    ( (This)->lpVtbl -> OnCommand(This,nCommandID) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IPluginWindowOwner_INTERFACE_DEFINED__ */


#ifndef __ILibraryBuilderPlugin_INTERFACE_DEFINED__
#define __ILibraryBuilderPlugin_INTERFACE_DEFINED__

/* interface ILibraryBuilderPlugin */
/* [oleautomation][uuid][object] */ 


EXTERN_C const IID IID_ILibraryBuilderPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("32496CEA-3B51-4f2f-9CE7-73D6AC942C34")
    ILibraryBuilderPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Process( 
            /* [in] */ BSTR sFile,
            /* [in] */ ISXMLElement *pXML) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryBuilderPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryBuilderPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryBuilderPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryBuilderPlugin * This);
        
        DECLSPEC_XFGVIRT(ILibraryBuilderPlugin, Process)
        HRESULT ( STDMETHODCALLTYPE *Process )( 
            ILibraryBuilderPlugin * This,
            /* [in] */ BSTR sFile,
            /* [in] */ ISXMLElement *pXML);
        
        END_INTERFACE
    } ILibraryBuilderPluginVtbl;

    interface ILibraryBuilderPlugin
    {
        CONST_VTBL struct ILibraryBuilderPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryBuilderPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryBuilderPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryBuilderPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryBuilderPlugin_Process(This,sFile,pXML)	\
    ( (This)->lpVtbl -> Process(This,sFile,pXML) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryBuilderPlugin_INTERFACE_DEFINED__ */


#ifndef __IImageServicePlugin_INTERFACE_DEFINED__
#define __IImageServicePlugin_INTERFACE_DEFINED__

/* interface IImageServicePlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IImageServicePlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("AB0A7BF2-94C0-4daa-8256-2BB6C3648050")
    IImageServicePlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE LoadFromFile( 
            /* [in] */ BSTR sFile,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [out] */ SAFEARRAY * *ppImage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE LoadFromMemory( 
            /* [in] */ BSTR sType,
            /* [in] */ SAFEARRAY * pMemory,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [out] */ SAFEARRAY * *ppImage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SaveToFile( 
            /* [in] */ BSTR sFile,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [in] */ SAFEARRAY * pImage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SaveToMemory( 
            /* [in] */ BSTR sType,
            /* [out] */ SAFEARRAY * *ppMemory,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [in] */ SAFEARRAY * pImage) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IImageServicePluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IImageServicePlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IImageServicePlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IImageServicePlugin * This);
        
        DECLSPEC_XFGVIRT(IImageServicePlugin, LoadFromFile)
        HRESULT ( STDMETHODCALLTYPE *LoadFromFile )( 
            IImageServicePlugin * This,
            /* [in] */ BSTR sFile,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [out] */ SAFEARRAY * *ppImage);
        
        DECLSPEC_XFGVIRT(IImageServicePlugin, LoadFromMemory)
        HRESULT ( STDMETHODCALLTYPE *LoadFromMemory )( 
            IImageServicePlugin * This,
            /* [in] */ BSTR sType,
            /* [in] */ SAFEARRAY * pMemory,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [out] */ SAFEARRAY * *ppImage);
        
        DECLSPEC_XFGVIRT(IImageServicePlugin, SaveToFile)
        HRESULT ( STDMETHODCALLTYPE *SaveToFile )( 
            IImageServicePlugin * This,
            /* [in] */ BSTR sFile,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [in] */ SAFEARRAY * pImage);
        
        DECLSPEC_XFGVIRT(IImageServicePlugin, SaveToMemory)
        HRESULT ( STDMETHODCALLTYPE *SaveToMemory )( 
            IImageServicePlugin * This,
            /* [in] */ BSTR sType,
            /* [out] */ SAFEARRAY * *ppMemory,
            /* [out][in] */ IMAGESERVICEDATA *pParams,
            /* [in] */ SAFEARRAY * pImage);
        
        END_INTERFACE
    } IImageServicePluginVtbl;

    interface IImageServicePlugin
    {
        CONST_VTBL struct IImageServicePluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IImageServicePlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IImageServicePlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IImageServicePlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IImageServicePlugin_LoadFromFile(This,sFile,pParams,ppImage)	\
    ( (This)->lpVtbl -> LoadFromFile(This,sFile,pParams,ppImage) ) 

#define IImageServicePlugin_LoadFromMemory(This,sType,pMemory,pParams,ppImage)	\
    ( (This)->lpVtbl -> LoadFromMemory(This,sType,pMemory,pParams,ppImage) ) 

#define IImageServicePlugin_SaveToFile(This,sFile,pParams,pImage)	\
    ( (This)->lpVtbl -> SaveToFile(This,sFile,pParams,pImage) ) 

#define IImageServicePlugin_SaveToMemory(This,sType,ppMemory,pParams,pImage)	\
    ( (This)->lpVtbl -> SaveToMemory(This,sType,ppMemory,pParams,pImage) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IImageServicePlugin_INTERFACE_DEFINED__ */


#ifndef __IDownloadPreviewSite_INTERFACE_DEFINED__
#define __IDownloadPreviewSite_INTERFACE_DEFINED__

/* interface IDownloadPreviewSite */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IDownloadPreviewSite;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("52A97CBD-2B99-45e8-B6F9-41E9CD583960")
    IDownloadPreviewSite : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetSuggestedFilename( 
            /* [retval][out] */ BSTR *psFile) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAvailableRanges( 
            /* [retval][out] */ SAFEARRAY * *pArray) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetProgressRange( 
            /* [in] */ DWORD nRange) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetProgressPosition( 
            /* [in] */ DWORD nPosition) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetProgressMessage( 
            /* [in] */ BSTR sMessage) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE QueueDeleteFile( 
            /* [in] */ BSTR sTempFile) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ExecuteFile( 
            /* [in] */ BSTR sFile) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IDownloadPreviewSiteVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDownloadPreviewSite * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDownloadPreviewSite * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDownloadPreviewSite * This);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, GetSuggestedFilename)
        HRESULT ( STDMETHODCALLTYPE *GetSuggestedFilename )( 
            IDownloadPreviewSite * This,
            /* [retval][out] */ BSTR *psFile);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, GetAvailableRanges)
        HRESULT ( STDMETHODCALLTYPE *GetAvailableRanges )( 
            IDownloadPreviewSite * This,
            /* [retval][out] */ SAFEARRAY * *pArray);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, SetProgressRange)
        HRESULT ( STDMETHODCALLTYPE *SetProgressRange )( 
            IDownloadPreviewSite * This,
            /* [in] */ DWORD nRange);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, SetProgressPosition)
        HRESULT ( STDMETHODCALLTYPE *SetProgressPosition )( 
            IDownloadPreviewSite * This,
            /* [in] */ DWORD nPosition);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, SetProgressMessage)
        HRESULT ( STDMETHODCALLTYPE *SetProgressMessage )( 
            IDownloadPreviewSite * This,
            /* [in] */ BSTR sMessage);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, QueueDeleteFile)
        HRESULT ( STDMETHODCALLTYPE *QueueDeleteFile )( 
            IDownloadPreviewSite * This,
            /* [in] */ BSTR sTempFile);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewSite, ExecuteFile)
        HRESULT ( STDMETHODCALLTYPE *ExecuteFile )( 
            IDownloadPreviewSite * This,
            /* [in] */ BSTR sFile);
        
        END_INTERFACE
    } IDownloadPreviewSiteVtbl;

    interface IDownloadPreviewSite
    {
        CONST_VTBL struct IDownloadPreviewSiteVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDownloadPreviewSite_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDownloadPreviewSite_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDownloadPreviewSite_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDownloadPreviewSite_GetSuggestedFilename(This,psFile)	\
    ( (This)->lpVtbl -> GetSuggestedFilename(This,psFile) ) 

#define IDownloadPreviewSite_GetAvailableRanges(This,pArray)	\
    ( (This)->lpVtbl -> GetAvailableRanges(This,pArray) ) 

#define IDownloadPreviewSite_SetProgressRange(This,nRange)	\
    ( (This)->lpVtbl -> SetProgressRange(This,nRange) ) 

#define IDownloadPreviewSite_SetProgressPosition(This,nPosition)	\
    ( (This)->lpVtbl -> SetProgressPosition(This,nPosition) ) 

#define IDownloadPreviewSite_SetProgressMessage(This,sMessage)	\
    ( (This)->lpVtbl -> SetProgressMessage(This,sMessage) ) 

#define IDownloadPreviewSite_QueueDeleteFile(This,sTempFile)	\
    ( (This)->lpVtbl -> QueueDeleteFile(This,sTempFile) ) 

#define IDownloadPreviewSite_ExecuteFile(This,sFile)	\
    ( (This)->lpVtbl -> ExecuteFile(This,sFile) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDownloadPreviewSite_INTERFACE_DEFINED__ */


#ifndef __IDownloadPreviewPlugin_INTERFACE_DEFINED__
#define __IDownloadPreviewPlugin_INTERFACE_DEFINED__

/* interface IDownloadPreviewPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IDownloadPreviewPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("1182FCD9-9F14-4e4a-BD05-432422B5BFAF")
    IDownloadPreviewPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetSite( 
            /* [in] */ IDownloadPreviewSite *pSite) = 0;
        
        virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE Preview( 
            /* [in] */ HANDLE hFile,
            /* [in] */ BSTR sTarget) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Cancel( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IDownloadPreviewPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDownloadPreviewPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDownloadPreviewPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDownloadPreviewPlugin * This);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, SetSite)
        HRESULT ( STDMETHODCALLTYPE *SetSite )( 
            IDownloadPreviewPlugin * This,
            /* [in] */ IDownloadPreviewSite *pSite);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, Preview)
        /* [helpstring] */ HRESULT ( STDMETHODCALLTYPE *Preview )( 
            IDownloadPreviewPlugin * This,
            /* [in] */ HANDLE hFile,
            /* [in] */ BSTR sTarget);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, Cancel)
        HRESULT ( STDMETHODCALLTYPE *Cancel )( 
            IDownloadPreviewPlugin * This);
        
        END_INTERFACE
    } IDownloadPreviewPluginVtbl;

    interface IDownloadPreviewPlugin
    {
        CONST_VTBL struct IDownloadPreviewPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDownloadPreviewPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDownloadPreviewPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDownloadPreviewPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDownloadPreviewPlugin_SetSite(This,pSite)	\
    ( (This)->lpVtbl -> SetSite(This,pSite) ) 

#define IDownloadPreviewPlugin_Preview(This,hFile,sTarget)	\
    ( (This)->lpVtbl -> Preview(This,hFile,sTarget) ) 

#define IDownloadPreviewPlugin_Cancel(This)	\
    ( (This)->lpVtbl -> Cancel(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDownloadPreviewPlugin_INTERFACE_DEFINED__ */


#ifndef __IDownloadPreviewPlugin2_INTERFACE_DEFINED__
#define __IDownloadPreviewPlugin2_INTERFACE_DEFINED__

/* interface IDownloadPreviewPlugin2 */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IDownloadPreviewPlugin2;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("7682913F-2AE7-44d6-852A-1AB1B913818C")
    IDownloadPreviewPlugin2 : public IDownloadPreviewPlugin
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Preview2( 
            /* [in] */ BSTR sSource,
            /* [in] */ BSTR sTarget) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IDownloadPreviewPlugin2Vtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDownloadPreviewPlugin2 * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDownloadPreviewPlugin2 * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDownloadPreviewPlugin2 * This);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, SetSite)
        HRESULT ( STDMETHODCALLTYPE *SetSite )( 
            IDownloadPreviewPlugin2 * This,
            /* [in] */ IDownloadPreviewSite *pSite);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, Preview)
        /* [helpstring] */ HRESULT ( STDMETHODCALLTYPE *Preview )( 
            IDownloadPreviewPlugin2 * This,
            /* [in] */ HANDLE hFile,
            /* [in] */ BSTR sTarget);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin, Cancel)
        HRESULT ( STDMETHODCALLTYPE *Cancel )( 
            IDownloadPreviewPlugin2 * This);
        
        DECLSPEC_XFGVIRT(IDownloadPreviewPlugin2, Preview2)
        HRESULT ( STDMETHODCALLTYPE *Preview2 )( 
            IDownloadPreviewPlugin2 * This,
            /* [in] */ BSTR sSource,
            /* [in] */ BSTR sTarget);
        
        END_INTERFACE
    } IDownloadPreviewPlugin2Vtbl;

    interface IDownloadPreviewPlugin2
    {
        CONST_VTBL struct IDownloadPreviewPlugin2Vtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDownloadPreviewPlugin2_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDownloadPreviewPlugin2_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDownloadPreviewPlugin2_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDownloadPreviewPlugin2_SetSite(This,pSite)	\
    ( (This)->lpVtbl -> SetSite(This,pSite) ) 

#define IDownloadPreviewPlugin2_Preview(This,hFile,sTarget)	\
    ( (This)->lpVtbl -> Preview(This,hFile,sTarget) ) 

#define IDownloadPreviewPlugin2_Cancel(This)	\
    ( (This)->lpVtbl -> Cancel(This) ) 


#define IDownloadPreviewPlugin2_Preview2(This,sSource,sTarget)	\
    ( (This)->lpVtbl -> Preview2(This,sSource,sTarget) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDownloadPreviewPlugin2_INTERFACE_DEFINED__ */


#ifndef __IAudioVisPlugin_INTERFACE_DEFINED__
#define __IAudioVisPlugin_INTERFACE_DEFINED__

/* interface IAudioVisPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IAudioVisPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("E788D125-4D41-4a35-A436-D1A1FD0C8EC9")
    IAudioVisPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Configure( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Create( 
            /* [in] */ HWND hWnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Destroy( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Reposition( 
            /* [in] */ RECT *prcWnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnTrackOpen( 
            /* [in] */ BSTR sName,
            /* [in] */ DWORD nLength) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnTrackClose( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnPlayStart( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnPlayStop( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OnChunk( 
            /* [in] */ MEDIAVISCHUNK *pChunk) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IAudioVisPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAudioVisPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, Configure)
        HRESULT ( STDMETHODCALLTYPE *Configure )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, Create)
        HRESULT ( STDMETHODCALLTYPE *Create )( 
            IAudioVisPlugin * This,
            /* [in] */ HWND hWnd);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, Destroy)
        HRESULT ( STDMETHODCALLTYPE *Destroy )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, Reposition)
        HRESULT ( STDMETHODCALLTYPE *Reposition )( 
            IAudioVisPlugin * This,
            /* [in] */ RECT *prcWnd);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, OnTrackOpen)
        HRESULT ( STDMETHODCALLTYPE *OnTrackOpen )( 
            IAudioVisPlugin * This,
            /* [in] */ BSTR sName,
            /* [in] */ DWORD nLength);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, OnTrackClose)
        HRESULT ( STDMETHODCALLTYPE *OnTrackClose )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, OnPlayStart)
        HRESULT ( STDMETHODCALLTYPE *OnPlayStart )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, OnPlayStop)
        HRESULT ( STDMETHODCALLTYPE *OnPlayStop )( 
            IAudioVisPlugin * This);
        
        DECLSPEC_XFGVIRT(IAudioVisPlugin, OnChunk)
        HRESULT ( STDMETHODCALLTYPE *OnChunk )( 
            IAudioVisPlugin * This,
            /* [in] */ MEDIAVISCHUNK *pChunk);
        
        END_INTERFACE
    } IAudioVisPluginVtbl;

    interface IAudioVisPlugin
    {
        CONST_VTBL struct IAudioVisPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IAudioVisPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IAudioVisPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IAudioVisPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IAudioVisPlugin_Configure(This)	\
    ( (This)->lpVtbl -> Configure(This) ) 

#define IAudioVisPlugin_Create(This,hWnd)	\
    ( (This)->lpVtbl -> Create(This,hWnd) ) 

#define IAudioVisPlugin_Destroy(This)	\
    ( (This)->lpVtbl -> Destroy(This) ) 

#define IAudioVisPlugin_Reposition(This,prcWnd)	\
    ( (This)->lpVtbl -> Reposition(This,prcWnd) ) 

#define IAudioVisPlugin_OnTrackOpen(This,sName,nLength)	\
    ( (This)->lpVtbl -> OnTrackOpen(This,sName,nLength) ) 

#define IAudioVisPlugin_OnTrackClose(This)	\
    ( (This)->lpVtbl -> OnTrackClose(This) ) 

#define IAudioVisPlugin_OnPlayStart(This)	\
    ( (This)->lpVtbl -> OnPlayStart(This) ) 

#define IAudioVisPlugin_OnPlayStop(This)	\
    ( (This)->lpVtbl -> OnPlayStop(This) ) 

#define IAudioVisPlugin_OnChunk(This,pChunk)	\
    ( (This)->lpVtbl -> OnChunk(This,pChunk) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IAudioVisPlugin_INTERFACE_DEFINED__ */


#ifndef __IMediaPlayer_INTERFACE_DEFINED__
#define __IMediaPlayer_INTERFACE_DEFINED__

/* interface IMediaPlayer */
/* [object][unique][oleautomation][uuid] */ 


EXTERN_C const IID IID_IMediaPlayer;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("59978299-C8AC-4818-83F4-C382BB611D5C")
    IMediaPlayer : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Create( 
            /* [in] */ HWND hWnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Destroy( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Reposition( 
            /* [in] */ RECT *prcWnd) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetLogoBitmap( 
            /* [in] */ HBITMAP hLogo) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetVolume( 
            /* [out] */ DOUBLE *pnVolume) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetVolume( 
            /* [in] */ DOUBLE nVolume) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetZoom( 
            /* [out] */ MediaZoom *pnZoom) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetZoom( 
            /* [in] */ MediaZoom nZoom) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetAspect( 
            /* [out] */ DOUBLE *pnAspect) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetAspect( 
            /* [in] */ DOUBLE nAspect) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Open( 
            /* [in] */ BSTR sFilename) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Close( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Play( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Pause( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Stop( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetState( 
            /* [out] */ MediaState *pnState) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetLength( 
            /* [out] */ LONGLONG *pnLength) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPosition( 
            /* [out] */ LONGLONG *pnPosition) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPosition( 
            /* [in] */ LONGLONG nPosition) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetSpeed( 
            /* [out] */ DOUBLE *pnSpeed) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetSpeed( 
            /* [in] */ DOUBLE nSpeed) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPlugin( 
            /* [out] */ IAudioVisPlugin **ppPlugin) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPlugin( 
            /* [in] */ IAudioVisPlugin *pPlugin) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetPluginSize( 
            /* [out] */ LONG *pnSize) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetPluginSize( 
            /* [in] */ LONG nSize) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IMediaPlayerVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IMediaPlayer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Create)
        HRESULT ( STDMETHODCALLTYPE *Create )( 
            IMediaPlayer * This,
            /* [in] */ HWND hWnd);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Destroy)
        HRESULT ( STDMETHODCALLTYPE *Destroy )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Reposition)
        HRESULT ( STDMETHODCALLTYPE *Reposition )( 
            IMediaPlayer * This,
            /* [in] */ RECT *prcWnd);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetLogoBitmap)
        HRESULT ( STDMETHODCALLTYPE *SetLogoBitmap )( 
            IMediaPlayer * This,
            /* [in] */ HBITMAP hLogo);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetVolume)
        HRESULT ( STDMETHODCALLTYPE *GetVolume )( 
            IMediaPlayer * This,
            /* [out] */ DOUBLE *pnVolume);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetVolume)
        HRESULT ( STDMETHODCALLTYPE *SetVolume )( 
            IMediaPlayer * This,
            /* [in] */ DOUBLE nVolume);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetZoom)
        HRESULT ( STDMETHODCALLTYPE *GetZoom )( 
            IMediaPlayer * This,
            /* [out] */ MediaZoom *pnZoom);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetZoom)
        HRESULT ( STDMETHODCALLTYPE *SetZoom )( 
            IMediaPlayer * This,
            /* [in] */ MediaZoom nZoom);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetAspect)
        HRESULT ( STDMETHODCALLTYPE *GetAspect )( 
            IMediaPlayer * This,
            /* [out] */ DOUBLE *pnAspect);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetAspect)
        HRESULT ( STDMETHODCALLTYPE *SetAspect )( 
            IMediaPlayer * This,
            /* [in] */ DOUBLE nAspect);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Open)
        HRESULT ( STDMETHODCALLTYPE *Open )( 
            IMediaPlayer * This,
            /* [in] */ BSTR sFilename);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Close)
        HRESULT ( STDMETHODCALLTYPE *Close )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Play)
        HRESULT ( STDMETHODCALLTYPE *Play )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Pause)
        HRESULT ( STDMETHODCALLTYPE *Pause )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, Stop)
        HRESULT ( STDMETHODCALLTYPE *Stop )( 
            IMediaPlayer * This);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetState)
        HRESULT ( STDMETHODCALLTYPE *GetState )( 
            IMediaPlayer * This,
            /* [out] */ MediaState *pnState);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetLength)
        HRESULT ( STDMETHODCALLTYPE *GetLength )( 
            IMediaPlayer * This,
            /* [out] */ LONGLONG *pnLength);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetPosition)
        HRESULT ( STDMETHODCALLTYPE *GetPosition )( 
            IMediaPlayer * This,
            /* [out] */ LONGLONG *pnPosition);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetPosition)
        HRESULT ( STDMETHODCALLTYPE *SetPosition )( 
            IMediaPlayer * This,
            /* [in] */ LONGLONG nPosition);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetSpeed)
        HRESULT ( STDMETHODCALLTYPE *GetSpeed )( 
            IMediaPlayer * This,
            /* [out] */ DOUBLE *pnSpeed);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetSpeed)
        HRESULT ( STDMETHODCALLTYPE *SetSpeed )( 
            IMediaPlayer * This,
            /* [in] */ DOUBLE nSpeed);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetPlugin)
        HRESULT ( STDMETHODCALLTYPE *GetPlugin )( 
            IMediaPlayer * This,
            /* [out] */ IAudioVisPlugin **ppPlugin);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetPlugin)
        HRESULT ( STDMETHODCALLTYPE *SetPlugin )( 
            IMediaPlayer * This,
            /* [in] */ IAudioVisPlugin *pPlugin);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, GetPluginSize)
        HRESULT ( STDMETHODCALLTYPE *GetPluginSize )( 
            IMediaPlayer * This,
            /* [out] */ LONG *pnSize);
        
        DECLSPEC_XFGVIRT(IMediaPlayer, SetPluginSize)
        HRESULT ( STDMETHODCALLTYPE *SetPluginSize )( 
            IMediaPlayer * This,
            /* [in] */ LONG nSize);
        
        END_INTERFACE
    } IMediaPlayerVtbl;

    interface IMediaPlayer
    {
        CONST_VTBL struct IMediaPlayerVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IMediaPlayer_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IMediaPlayer_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IMediaPlayer_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IMediaPlayer_Create(This,hWnd)	\
    ( (This)->lpVtbl -> Create(This,hWnd) ) 

#define IMediaPlayer_Destroy(This)	\
    ( (This)->lpVtbl -> Destroy(This) ) 

#define IMediaPlayer_Reposition(This,prcWnd)	\
    ( (This)->lpVtbl -> Reposition(This,prcWnd) ) 

#define IMediaPlayer_SetLogoBitmap(This,hLogo)	\
    ( (This)->lpVtbl -> SetLogoBitmap(This,hLogo) ) 

#define IMediaPlayer_GetVolume(This,pnVolume)	\
    ( (This)->lpVtbl -> GetVolume(This,pnVolume) ) 

#define IMediaPlayer_SetVolume(This,nVolume)	\
    ( (This)->lpVtbl -> SetVolume(This,nVolume) ) 

#define IMediaPlayer_GetZoom(This,pnZoom)	\
    ( (This)->lpVtbl -> GetZoom(This,pnZoom) ) 

#define IMediaPlayer_SetZoom(This,nZoom)	\
    ( (This)->lpVtbl -> SetZoom(This,nZoom) ) 

#define IMediaPlayer_GetAspect(This,pnAspect)	\
    ( (This)->lpVtbl -> GetAspect(This,pnAspect) ) 

#define IMediaPlayer_SetAspect(This,nAspect)	\
    ( (This)->lpVtbl -> SetAspect(This,nAspect) ) 

#define IMediaPlayer_Open(This,sFilename)	\
    ( (This)->lpVtbl -> Open(This,sFilename) ) 

#define IMediaPlayer_Close(This)	\
    ( (This)->lpVtbl -> Close(This) ) 

#define IMediaPlayer_Play(This)	\
    ( (This)->lpVtbl -> Play(This) ) 

#define IMediaPlayer_Pause(This)	\
    ( (This)->lpVtbl -> Pause(This) ) 

#define IMediaPlayer_Stop(This)	\
    ( (This)->lpVtbl -> Stop(This) ) 

#define IMediaPlayer_GetState(This,pnState)	\
    ( (This)->lpVtbl -> GetState(This,pnState) ) 

#define IMediaPlayer_GetLength(This,pnLength)	\
    ( (This)->lpVtbl -> GetLength(This,pnLength) ) 

#define IMediaPlayer_GetPosition(This,pnPosition)	\
    ( (This)->lpVtbl -> GetPosition(This,pnPosition) ) 

#define IMediaPlayer_SetPosition(This,nPosition)	\
    ( (This)->lpVtbl -> SetPosition(This,nPosition) ) 

#define IMediaPlayer_GetSpeed(This,pnSpeed)	\
    ( (This)->lpVtbl -> GetSpeed(This,pnSpeed) ) 

#define IMediaPlayer_SetSpeed(This,nSpeed)	\
    ( (This)->lpVtbl -> SetSpeed(This,nSpeed) ) 

#define IMediaPlayer_GetPlugin(This,ppPlugin)	\
    ( (This)->lpVtbl -> GetPlugin(This,ppPlugin) ) 

#define IMediaPlayer_SetPlugin(This,pPlugin)	\
    ( (This)->lpVtbl -> SetPlugin(This,pPlugin) ) 

#define IMediaPlayer_GetPluginSize(This,pnSize)	\
    ( (This)->lpVtbl -> GetPluginSize(This,pnSize) ) 

#define IMediaPlayer_SetPluginSize(This,nSize)	\
    ( (This)->lpVtbl -> SetPluginSize(This,nSize) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IMediaPlayer_INTERFACE_DEFINED__ */


#ifndef __IWrappedPluginControl_INTERFACE_DEFINED__
#define __IWrappedPluginControl_INTERFACE_DEFINED__

/* interface IWrappedPluginControl */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_IWrappedPluginControl;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("71045028-F95C-4c03-AB09-6D906DBFC731")
    IWrappedPluginControl : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Load( 
            /* [in] */ BSTR sDLL,
            /* [in] */ LONG nIndex) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Unload( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Enumerate( 
            /* [out] */ LPSAFEARRAY *ppArray) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IWrappedPluginControlVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IWrappedPluginControl * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IWrappedPluginControl * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IWrappedPluginControl * This);
        
        DECLSPEC_XFGVIRT(IWrappedPluginControl, Load)
        HRESULT ( STDMETHODCALLTYPE *Load )( 
            IWrappedPluginControl * This,
            /* [in] */ BSTR sDLL,
            /* [in] */ LONG nIndex);
        
        DECLSPEC_XFGVIRT(IWrappedPluginControl, Unload)
        HRESULT ( STDMETHODCALLTYPE *Unload )( 
            IWrappedPluginControl * This);
        
        DECLSPEC_XFGVIRT(IWrappedPluginControl, Enumerate)
        HRESULT ( STDMETHODCALLTYPE *Enumerate )( 
            IWrappedPluginControl * This,
            /* [out] */ LPSAFEARRAY *ppArray);
        
        END_INTERFACE
    } IWrappedPluginControlVtbl;

    interface IWrappedPluginControl
    {
        CONST_VTBL struct IWrappedPluginControlVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IWrappedPluginControl_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IWrappedPluginControl_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IWrappedPluginControl_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IWrappedPluginControl_Load(This,sDLL,nIndex)	\
    ( (This)->lpVtbl -> Load(This,sDLL,nIndex) ) 

#define IWrappedPluginControl_Unload(This)	\
    ( (This)->lpVtbl -> Unload(This) ) 

#define IWrappedPluginControl_Enumerate(This,ppArray)	\
    ( (This)->lpVtbl -> Enumerate(This,ppArray) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IWrappedPluginControl_INTERFACE_DEFINED__ */


#ifndef __IUserInterface_INTERFACE_DEFINED__
#define __IUserInterface_INTERFACE_DEFINED__

/* interface IUserInterface */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_IUserInterface;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("FCDE733E-DDA0-4849-AD83-D02B0F4D1DA3")
    IUserInterface : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_UserInterface( 
            /* [retval][out] */ IUserInterface **ppUserInterface) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE NewWindow( 
            /* [in] */ BSTR bsName,
            /* [in] */ IPluginWindowOwner *pOwner,
            /* [retval][out] */ IPluginWindow **ppWindow) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_MainWindowHwnd( 
            /* [retval][out] */ HWND *phWnd) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ActiveView( 
            /* [retval][out] */ IGenericView **ppView) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE RegisterCommand( 
            /* [in] */ BSTR bsName,
            /* [in] */ HICON hIcon,
            /* [retval][out] */ UINT *pnCommandID) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE AddFromString( 
            /* [in] */ BSTR sXML) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE AddFromResource( 
            /* [in] */ HINSTANCE hInstance,
            /* [in] */ UINT nID) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE AddFromXML( 
            /* [in] */ ISXMLElement *pXML) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE GetMenu( 
            /* [in] */ BSTR bsName,
            /* [in] */ VARIANT_BOOL bCreate,
            /* [retval][out] */ ISMenu **ppMenu) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE GetToolbar( 
            /* [in] */ BSTR bsName,
            /* [in] */ VARIANT_BOOL bCreate,
            /* [retval][out] */ ISToolbar **ppToolbar) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE NameToID( 
            /* [in] */ BSTR bsName,
            /* [retval][out] */ UINT *pnCommandID) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE AddString( 
            /* [in] */ UINT nStringID,
            /* [in] */ BSTR sText) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE LoadString( 
            /* [in] */ UINT nStringID,
            /* [retval][out] */ BSTR *psText) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IUserInterfaceVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IUserInterface * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IUserInterface * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IUserInterface * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IUserInterface * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IUserInterface * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IUserInterface * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IUserInterface * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(IUserInterface, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            IUserInterface * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(IUserInterface, get_UserInterface)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_UserInterface )( 
            IUserInterface * This,
            /* [retval][out] */ IUserInterface **ppUserInterface);
        
        DECLSPEC_XFGVIRT(IUserInterface, NewWindow)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *NewWindow )( 
            IUserInterface * This,
            /* [in] */ BSTR bsName,
            /* [in] */ IPluginWindowOwner *pOwner,
            /* [retval][out] */ IPluginWindow **ppWindow);
        
        DECLSPEC_XFGVIRT(IUserInterface, get_MainWindowHwnd)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_MainWindowHwnd )( 
            IUserInterface * This,
            /* [retval][out] */ HWND *phWnd);
        
        DECLSPEC_XFGVIRT(IUserInterface, get_ActiveView)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ActiveView )( 
            IUserInterface * This,
            /* [retval][out] */ IGenericView **ppView);
        
        DECLSPEC_XFGVIRT(IUserInterface, RegisterCommand)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *RegisterCommand )( 
            IUserInterface * This,
            /* [in] */ BSTR bsName,
            /* [in] */ HICON hIcon,
            /* [retval][out] */ UINT *pnCommandID);
        
        DECLSPEC_XFGVIRT(IUserInterface, AddFromString)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *AddFromString )( 
            IUserInterface * This,
            /* [in] */ BSTR sXML);
        
        DECLSPEC_XFGVIRT(IUserInterface, AddFromResource)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *AddFromResource )( 
            IUserInterface * This,
            /* [in] */ HINSTANCE hInstance,
            /* [in] */ UINT nID);
        
        DECLSPEC_XFGVIRT(IUserInterface, AddFromXML)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *AddFromXML )( 
            IUserInterface * This,
            /* [in] */ ISXMLElement *pXML);
        
        DECLSPEC_XFGVIRT(IUserInterface, GetMenu)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *GetMenu )( 
            IUserInterface * This,
            /* [in] */ BSTR bsName,
            /* [in] */ VARIANT_BOOL bCreate,
            /* [retval][out] */ ISMenu **ppMenu);
        
        DECLSPEC_XFGVIRT(IUserInterface, GetToolbar)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *GetToolbar )( 
            IUserInterface * This,
            /* [in] */ BSTR bsName,
            /* [in] */ VARIANT_BOOL bCreate,
            /* [retval][out] */ ISToolbar **ppToolbar);
        
        DECLSPEC_XFGVIRT(IUserInterface, NameToID)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *NameToID )( 
            IUserInterface * This,
            /* [in] */ BSTR bsName,
            /* [retval][out] */ UINT *pnCommandID);
        
        DECLSPEC_XFGVIRT(IUserInterface, AddString)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *AddString )( 
            IUserInterface * This,
            /* [in] */ UINT nStringID,
            /* [in] */ BSTR sText);
        
        DECLSPEC_XFGVIRT(IUserInterface, LoadString)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *LoadString )( 
            IUserInterface * This,
            /* [in] */ UINT nStringID,
            /* [retval][out] */ BSTR *psText);
        
        END_INTERFACE
    } IUserInterfaceVtbl;

    interface IUserInterface
    {
        CONST_VTBL struct IUserInterfaceVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IUserInterface_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IUserInterface_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IUserInterface_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IUserInterface_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IUserInterface_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IUserInterface_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IUserInterface_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IUserInterface_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define IUserInterface_get_UserInterface(This,ppUserInterface)	\
    ( (This)->lpVtbl -> get_UserInterface(This,ppUserInterface) ) 

#define IUserInterface_NewWindow(This,bsName,pOwner,ppWindow)	\
    ( (This)->lpVtbl -> NewWindow(This,bsName,pOwner,ppWindow) ) 

#define IUserInterface_get_MainWindowHwnd(This,phWnd)	\
    ( (This)->lpVtbl -> get_MainWindowHwnd(This,phWnd) ) 

#define IUserInterface_get_ActiveView(This,ppView)	\
    ( (This)->lpVtbl -> get_ActiveView(This,ppView) ) 

#define IUserInterface_RegisterCommand(This,bsName,hIcon,pnCommandID)	\
    ( (This)->lpVtbl -> RegisterCommand(This,bsName,hIcon,pnCommandID) ) 

#define IUserInterface_AddFromString(This,sXML)	\
    ( (This)->lpVtbl -> AddFromString(This,sXML) ) 

#define IUserInterface_AddFromResource(This,hInstance,nID)	\
    ( (This)->lpVtbl -> AddFromResource(This,hInstance,nID) ) 

#define IUserInterface_AddFromXML(This,pXML)	\
    ( (This)->lpVtbl -> AddFromXML(This,pXML) ) 

#define IUserInterface_GetMenu(This,bsName,bCreate,ppMenu)	\
    ( (This)->lpVtbl -> GetMenu(This,bsName,bCreate,ppMenu) ) 

#define IUserInterface_GetToolbar(This,bsName,bCreate,ppToolbar)	\
    ( (This)->lpVtbl -> GetToolbar(This,bsName,bCreate,ppToolbar) ) 

#define IUserInterface_NameToID(This,bsName,pnCommandID)	\
    ( (This)->lpVtbl -> NameToID(This,bsName,pnCommandID) ) 

#define IUserInterface_AddString(This,nStringID,sText)	\
    ( (This)->lpVtbl -> AddString(This,nStringID,sText) ) 

#define IUserInterface_LoadString(This,nStringID,psText)	\
    ( (This)->lpVtbl -> LoadString(This,nStringID,psText) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IUserInterface_INTERFACE_DEFINED__ */


#ifndef __ILibrary_INTERFACE_DEFINED__
#define __ILibrary_INTERFACE_DEFINED__

/* interface ILibrary */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ILibrary;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("1735A63C-099B-414c-9B22-817C2FC5EC34")
    ILibrary : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Folders( 
            /* [retval][out] */ ILibraryFolders **ppFolders) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Albums( 
            /* [retval][out] */ IUnknown **ppAlbums) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Files( 
            /* [retval][out] */ ILibraryFiles **ppFiles) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE FindByName( 
            /* [in] */ BSTR sName,
            /* [retval][out] */ ILibraryFile **ppFile) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE FindByPath( 
            /* [in] */ BSTR sPath,
            /* [retval][out] */ ILibraryFile **ppFile) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE FindByURN( 
            /* [in] */ BSTR sURN,
            /* [retval][out] */ ILibraryFile **ppFile) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE FindByIndex( 
            /* [in] */ LONG nIndex,
            /* [retval][out] */ ILibraryFile **ppFile) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibrary * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibrary * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibrary * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ILibrary * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ILibrary * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ILibrary * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ILibrary * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ILibrary, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ILibrary * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ILibrary, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            ILibrary * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(ILibrary, get_Folders)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Folders )( 
            ILibrary * This,
            /* [retval][out] */ ILibraryFolders **ppFolders);
        
        DECLSPEC_XFGVIRT(ILibrary, get_Albums)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Albums )( 
            ILibrary * This,
            /* [retval][out] */ IUnknown **ppAlbums);
        
        DECLSPEC_XFGVIRT(ILibrary, get_Files)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Files )( 
            ILibrary * This,
            /* [retval][out] */ ILibraryFiles **ppFiles);
        
        DECLSPEC_XFGVIRT(ILibrary, FindByName)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *FindByName )( 
            ILibrary * This,
            /* [in] */ BSTR sName,
            /* [retval][out] */ ILibraryFile **ppFile);
        
        DECLSPEC_XFGVIRT(ILibrary, FindByPath)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *FindByPath )( 
            ILibrary * This,
            /* [in] */ BSTR sPath,
            /* [retval][out] */ ILibraryFile **ppFile);
        
        DECLSPEC_XFGVIRT(ILibrary, FindByURN)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *FindByURN )( 
            ILibrary * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ ILibraryFile **ppFile);
        
        DECLSPEC_XFGVIRT(ILibrary, FindByIndex)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *FindByIndex )( 
            ILibrary * This,
            /* [in] */ LONG nIndex,
            /* [retval][out] */ ILibraryFile **ppFile);
        
        END_INTERFACE
    } ILibraryVtbl;

    interface ILibrary
    {
        CONST_VTBL struct ILibraryVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibrary_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibrary_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibrary_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibrary_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ILibrary_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ILibrary_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ILibrary_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ILibrary_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ILibrary_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define ILibrary_get_Folders(This,ppFolders)	\
    ( (This)->lpVtbl -> get_Folders(This,ppFolders) ) 

#define ILibrary_get_Albums(This,ppAlbums)	\
    ( (This)->lpVtbl -> get_Albums(This,ppAlbums) ) 

#define ILibrary_get_Files(This,ppFiles)	\
    ( (This)->lpVtbl -> get_Files(This,ppFiles) ) 

#define ILibrary_FindByName(This,sName,ppFile)	\
    ( (This)->lpVtbl -> FindByName(This,sName,ppFile) ) 

#define ILibrary_FindByPath(This,sPath,ppFile)	\
    ( (This)->lpVtbl -> FindByPath(This,sPath,ppFile) ) 

#define ILibrary_FindByURN(This,sURN,ppFile)	\
    ( (This)->lpVtbl -> FindByURN(This,sURN,ppFile) ) 

#define ILibrary_FindByIndex(This,nIndex,ppFile)	\
    ( (This)->lpVtbl -> FindByIndex(This,nIndex,ppFile) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibrary_INTERFACE_DEFINED__ */


#ifndef __ISettings_INTERFACE_DEFINED__
#define __ISettings_INTERFACE_DEFINED__

/* interface ISettings */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ISettings;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("FDDC655E-6CA6-4575-A167-1FD48AAC54EF")
    ISettings : public IDispatch
    {
    public:
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE GetValue( 
            /* [out][in] */ VARIANT *value) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISettingsVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISettings * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISettings * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISettings * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISettings * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISettings * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISettings * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISettings * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISettings, GetValue)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *GetValue )( 
            ISettings * This,
            /* [out][in] */ VARIANT *value);
        
        END_INTERFACE
    } ISettingsVtbl;

    interface ISettings
    {
        CONST_VTBL struct ISettingsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISettings_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISettings_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISettings_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISettings_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISettings_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISettings_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISettings_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISettings_GetValue(This,value)	\
    ( (This)->lpVtbl -> GetValue(This,value) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISettings_INTERFACE_DEFINED__ */


#ifndef __ISMenu_INTERFACE_DEFINED__
#define __ISMenu_INTERFACE_DEFINED__

/* interface ISMenu */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ISMenu;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("D8C3C592-5AF4-44cf-8AA8-59038FE38812")
    ISMenu : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_UserInterface( 
            /* [retval][out] */ IUserInterface **ppUserInterface) = 0;
        
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISMenu **ppMenu) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ItemType( 
            /* [retval][out] */ SMenuType *pnType) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_CommandID( 
            /* [retval][out] */ LONG *pnCommandID) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_CommandID( 
            /* [in] */ LONG nCommandID) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Text( 
            /* [retval][out] */ BSTR *psText) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Text( 
            /* [in] */ BSTR sText) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_HotKey( 
            /* [retval][out] */ BSTR *psText) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_HotKey( 
            /* [in] */ BSTR sText) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Remove( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE InsertSeparator( 
            /* [in] */ LONG nPosition) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE InsertMenu( 
            /* [in] */ LONG nPosition,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISMenu **ppMenu) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE InsertCommand( 
            /* [in] */ LONG nPosition,
            /* [in] */ LONG nCommandID,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISMenu **ppMenu) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Position( 
            /* [retval][out] */ LONG *pnCommandID) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Parent( 
            /* [retval][out] */ ISMenu **ppMenu) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISMenuVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISMenu * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISMenu * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISMenu * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISMenu * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISMenu * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISMenu * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISMenu * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ISMenu * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ISMenu, get_UserInterface)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_UserInterface )( 
            ISMenu * This,
            /* [retval][out] */ IUserInterface **ppUserInterface);
        
        DECLSPEC_XFGVIRT(ISMenu, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ISMenu * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ISMenu * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ISMenu **ppMenu);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ISMenu * This,
            /* [retval][out] */ LONG *pnCount);
        
        DECLSPEC_XFGVIRT(ISMenu, get_ItemType)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ItemType )( 
            ISMenu * This,
            /* [retval][out] */ SMenuType *pnType);
        
        DECLSPEC_XFGVIRT(ISMenu, get_CommandID)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_CommandID )( 
            ISMenu * This,
            /* [retval][out] */ LONG *pnCommandID);
        
        DECLSPEC_XFGVIRT(ISMenu, put_CommandID)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_CommandID )( 
            ISMenu * This,
            /* [in] */ LONG nCommandID);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Text)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Text )( 
            ISMenu * This,
            /* [retval][out] */ BSTR *psText);
        
        DECLSPEC_XFGVIRT(ISMenu, put_Text)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Text )( 
            ISMenu * This,
            /* [in] */ BSTR sText);
        
        DECLSPEC_XFGVIRT(ISMenu, get_HotKey)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_HotKey )( 
            ISMenu * This,
            /* [retval][out] */ BSTR *psText);
        
        DECLSPEC_XFGVIRT(ISMenu, put_HotKey)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_HotKey )( 
            ISMenu * This,
            /* [in] */ BSTR sText);
        
        DECLSPEC_XFGVIRT(ISMenu, Remove)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Remove )( 
            ISMenu * This);
        
        DECLSPEC_XFGVIRT(ISMenu, InsertSeparator)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *InsertSeparator )( 
            ISMenu * This,
            /* [in] */ LONG nPosition);
        
        DECLSPEC_XFGVIRT(ISMenu, InsertMenu)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *InsertMenu )( 
            ISMenu * This,
            /* [in] */ LONG nPosition,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISMenu **ppMenu);
        
        DECLSPEC_XFGVIRT(ISMenu, InsertCommand)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *InsertCommand )( 
            ISMenu * This,
            /* [in] */ LONG nPosition,
            /* [in] */ LONG nCommandID,
            /* [in] */ BSTR sText,
            /* [retval][out] */ ISMenu **ppMenu);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Position)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Position )( 
            ISMenu * This,
            /* [retval][out] */ LONG *pnCommandID);
        
        DECLSPEC_XFGVIRT(ISMenu, get_Parent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Parent )( 
            ISMenu * This,
            /* [retval][out] */ ISMenu **ppMenu);
        
        END_INTERFACE
    } ISMenuVtbl;

    interface ISMenu
    {
        CONST_VTBL struct ISMenuVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISMenu_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISMenu_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISMenu_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISMenu_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISMenu_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISMenu_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISMenu_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISMenu_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ISMenu_get_UserInterface(This,ppUserInterface)	\
    ( (This)->lpVtbl -> get_UserInterface(This,ppUserInterface) ) 

#define ISMenu_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ISMenu_get_Item(This,vIndex,ppMenu)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppMenu) ) 

#define ISMenu_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#define ISMenu_get_ItemType(This,pnType)	\
    ( (This)->lpVtbl -> get_ItemType(This,pnType) ) 

#define ISMenu_get_CommandID(This,pnCommandID)	\
    ( (This)->lpVtbl -> get_CommandID(This,pnCommandID) ) 

#define ISMenu_put_CommandID(This,nCommandID)	\
    ( (This)->lpVtbl -> put_CommandID(This,nCommandID) ) 

#define ISMenu_get_Text(This,psText)	\
    ( (This)->lpVtbl -> get_Text(This,psText) ) 

#define ISMenu_put_Text(This,sText)	\
    ( (This)->lpVtbl -> put_Text(This,sText) ) 

#define ISMenu_get_HotKey(This,psText)	\
    ( (This)->lpVtbl -> get_HotKey(This,psText) ) 

#define ISMenu_put_HotKey(This,sText)	\
    ( (This)->lpVtbl -> put_HotKey(This,sText) ) 

#define ISMenu_Remove(This)	\
    ( (This)->lpVtbl -> Remove(This) ) 

#define ISMenu_InsertSeparator(This,nPosition)	\
    ( (This)->lpVtbl -> InsertSeparator(This,nPosition) ) 

#define ISMenu_InsertMenu(This,nPosition,sText,ppMenu)	\
    ( (This)->lpVtbl -> InsertMenu(This,nPosition,sText,ppMenu) ) 

#define ISMenu_InsertCommand(This,nPosition,nCommandID,sText,ppMenu)	\
    ( (This)->lpVtbl -> InsertCommand(This,nPosition,nCommandID,sText,ppMenu) ) 

#define ISMenu_get_Position(This,pnCommandID)	\
    ( (This)->lpVtbl -> get_Position(This,pnCommandID) ) 

#define ISMenu_get_Parent(This,ppMenu)	\
    ( (This)->lpVtbl -> get_Parent(This,ppMenu) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISMenu_INTERFACE_DEFINED__ */


#ifndef __ISToolbarItem_INTERFACE_DEFINED__
#define __ISToolbarItem_INTERFACE_DEFINED__

/* interface ISToolbarItem */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ISToolbarItem;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("3A82A3A3-5560-4ece-B38A-D56E1E74642A")
    ISToolbarItem : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_UserInterface( 
            /* [retval][out] */ IUserInterface **ppUserInterface) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Toolbar( 
            /* [retval][out] */ ISToolbar **ppToolbar) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ItemType( 
            /* [retval][out] */ SToolbarType *pnType) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_CommandID( 
            /* [retval][out] */ LONG *pnCommandID) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_CommandID( 
            /* [in] */ LONG nCommandID) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Text( 
            /* [retval][out] */ BSTR *psText) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Text( 
            /* [in] */ BSTR sText) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Remove( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ISToolbarItemVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ISToolbarItem * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ISToolbarItem * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ISToolbarItem * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ISToolbarItem * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ISToolbarItem * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ISToolbarItem * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ISToolbarItem * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ISToolbarItem * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_UserInterface)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_UserInterface )( 
            ISToolbarItem * This,
            /* [retval][out] */ IUserInterface **ppUserInterface);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_Toolbar)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Toolbar )( 
            ISToolbarItem * This,
            /* [retval][out] */ ISToolbar **ppToolbar);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_ItemType)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ItemType )( 
            ISToolbarItem * This,
            /* [retval][out] */ SToolbarType *pnType);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_CommandID)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_CommandID )( 
            ISToolbarItem * This,
            /* [retval][out] */ LONG *pnCommandID);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, put_CommandID)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_CommandID )( 
            ISToolbarItem * This,
            /* [in] */ LONG nCommandID);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, get_Text)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Text )( 
            ISToolbarItem * This,
            /* [retval][out] */ BSTR *psText);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, put_Text)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Text )( 
            ISToolbarItem * This,
            /* [in] */ BSTR sText);
        
        DECLSPEC_XFGVIRT(ISToolbarItem, Remove)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Remove )( 
            ISToolbarItem * This);
        
        END_INTERFACE
    } ISToolbarItemVtbl;

    interface ISToolbarItem
    {
        CONST_VTBL struct ISToolbarItemVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ISToolbarItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ISToolbarItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ISToolbarItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ISToolbarItem_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ISToolbarItem_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ISToolbarItem_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ISToolbarItem_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ISToolbarItem_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ISToolbarItem_get_UserInterface(This,ppUserInterface)	\
    ( (This)->lpVtbl -> get_UserInterface(This,ppUserInterface) ) 

#define ISToolbarItem_get_Toolbar(This,ppToolbar)	\
    ( (This)->lpVtbl -> get_Toolbar(This,ppToolbar) ) 

#define ISToolbarItem_get_ItemType(This,pnType)	\
    ( (This)->lpVtbl -> get_ItemType(This,pnType) ) 

#define ISToolbarItem_get_CommandID(This,pnCommandID)	\
    ( (This)->lpVtbl -> get_CommandID(This,pnCommandID) ) 

#define ISToolbarItem_put_CommandID(This,nCommandID)	\
    ( (This)->lpVtbl -> put_CommandID(This,nCommandID) ) 

#define ISToolbarItem_get_Text(This,psText)	\
    ( (This)->lpVtbl -> get_Text(This,psText) ) 

#define ISToolbarItem_put_Text(This,sText)	\
    ( (This)->lpVtbl -> put_Text(This,sText) ) 

#define ISToolbarItem_Remove(This)	\
    ( (This)->lpVtbl -> Remove(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ISToolbarItem_INTERFACE_DEFINED__ */


#ifndef __IGenericView_INTERFACE_DEFINED__
#define __IGenericView_INTERFACE_DEFINED__

/* interface IGenericView */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_IGenericView;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("EBAD02A1-E1B0-4961-9415-83267B2A5010")
    IGenericView : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Name( 
            /* [retval][out] */ BSTR *psName) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Unknown( 
            /* [retval][out] */ IUnknown **ppUnknown) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Param( 
            /* [retval][out] */ LONG *pnParam) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ VARIANT *pvItem) = 0;
        
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IGenericViewVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGenericView * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGenericView * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGenericView * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IGenericView * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IGenericView * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IGenericView * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IGenericView * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(IGenericView, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            IGenericView * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(IGenericView, get_Unknown)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Unknown )( 
            IGenericView * This,
            /* [retval][out] */ IUnknown **ppUnknown);
        
        DECLSPEC_XFGVIRT(IGenericView, get_Param)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Param )( 
            IGenericView * This,
            /* [retval][out] */ LONG *pnParam);
        
        DECLSPEC_XFGVIRT(IGenericView, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            IGenericView * This,
            /* [retval][out] */ LONG *pnCount);
        
        DECLSPEC_XFGVIRT(IGenericView, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            IGenericView * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ VARIANT *pvItem);
        
        DECLSPEC_XFGVIRT(IGenericView, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            IGenericView * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        END_INTERFACE
    } IGenericViewVtbl;

    interface IGenericView
    {
        CONST_VTBL struct IGenericViewVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IGenericView_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IGenericView_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IGenericView_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IGenericView_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IGenericView_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IGenericView_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IGenericView_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IGenericView_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define IGenericView_get_Unknown(This,ppUnknown)	\
    ( (This)->lpVtbl -> get_Unknown(This,ppUnknown) ) 

#define IGenericView_get_Param(This,pnParam)	\
    ( (This)->lpVtbl -> get_Param(This,pnParam) ) 

#define IGenericView_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#define IGenericView_get_Item(This,vIndex,pvItem)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,pvItem) ) 

#define IGenericView_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IGenericView_INTERFACE_DEFINED__ */


#ifndef __IEnvyFile_INTERFACE_DEFINED__
#define __IEnvyFile_INTERFACE_DEFINED__

/* interface IEnvyFile */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_IEnvyFile;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("B43A9B10-3F72-4a96-BD40-C3B643FDF2F3")
    IEnvyFile : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Path( 
            /* [retval][out] */ BSTR *psPath) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Name( 
            /* [retval][out] */ BSTR *psName) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Size( 
            /* [retval][out] */ ULONGLONG *pnSize) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_URN( 
            /* [in] */ BSTR sURN,
            /* [retval][out] */ BSTR *psURN) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Hash( 
            /* [in] */ URN_TYPE nType,
            /* [in] */ ENCODING nEncoding,
            /* [retval][out] */ BSTR *psURN) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_URL( 
            /* [retval][out] */ BSTR *psURL) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Magnet( 
            /* [retval][out] */ BSTR *psMagnet) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IEnvyFileVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IEnvyFile * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IEnvyFile * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IEnvyFile * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IEnvyFile * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IEnvyFile * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IEnvyFile * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IEnvyFile * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Path)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Path )( 
            IEnvyFile * This,
            /* [retval][out] */ BSTR *psPath);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            IEnvyFile * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Size)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            IEnvyFile * This,
            /* [retval][out] */ ULONGLONG *pnSize);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_URN)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_URN )( 
            IEnvyFile * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ BSTR *psURN);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Hash)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Hash )( 
            IEnvyFile * This,
            /* [in] */ URN_TYPE nType,
            /* [in] */ ENCODING nEncoding,
            /* [retval][out] */ BSTR *psURN);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_URL)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_URL )( 
            IEnvyFile * This,
            /* [retval][out] */ BSTR *psURL);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Magnet)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Magnet )( 
            IEnvyFile * This,
            /* [retval][out] */ BSTR *psMagnet);
        
        END_INTERFACE
    } IEnvyFileVtbl;

    interface IEnvyFile
    {
        CONST_VTBL struct IEnvyFileVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IEnvyFile_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IEnvyFile_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IEnvyFile_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IEnvyFile_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IEnvyFile_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IEnvyFile_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IEnvyFile_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IEnvyFile_get_Path(This,psPath)	\
    ( (This)->lpVtbl -> get_Path(This,psPath) ) 

#define IEnvyFile_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define IEnvyFile_get_Size(This,pnSize)	\
    ( (This)->lpVtbl -> get_Size(This,pnSize) ) 

#define IEnvyFile_get_URN(This,sURN,psURN)	\
    ( (This)->lpVtbl -> get_URN(This,sURN,psURN) ) 

#define IEnvyFile_get_Hash(This,nType,nEncoding,psURN)	\
    ( (This)->lpVtbl -> get_Hash(This,nType,nEncoding,psURN) ) 

#define IEnvyFile_get_URL(This,psURL)	\
    ( (This)->lpVtbl -> get_URL(This,psURL) ) 

#define IEnvyFile_get_Magnet(This,psMagnet)	\
    ( (This)->lpVtbl -> get_Magnet(This,psMagnet) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IEnvyFile_INTERFACE_DEFINED__ */


#ifndef __ILibraryFile_INTERFACE_DEFINED__
#define __ILibraryFile_INTERFACE_DEFINED__

/* interface ILibraryFile */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ILibraryFile;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("B663F7DE-E1C6-4fe6-92BD-D0549B7601E3")
    ILibraryFile : public IEnvyFile
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Folder( 
            /* [retval][out] */ ILibraryFolder **ppFolder) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Shared( 
            /* [retval][out] */ TRISTATE *pnValue) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Shared( 
            /* [in] */ TRISTATE nValue) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_EffectiveShared( 
            /* [retval][out] */ VARIANT_BOOL *pbValue) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Index( 
            /* [retval][out] */ LONG *pnIndex) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_MetadataAuto( 
            /* [retval][out] */ VARIANT_BOOL *pbValue) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Metadata( 
            /* [retval][out] */ ISXMLElement **ppXML) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Metadata( 
            /* [in] */ ISXMLElement *pXML) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Execute( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Delete( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Rename( 
            /* [in] */ BSTR sNewName) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Copy( 
            /* [in] */ BSTR sNewPath) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Move( 
            /* [in] */ BSTR sNewPath) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE MergeMetadata( 
            /* [in] */ ISXMLElement *pXML,
            /* [in] */ VARIANT_BOOL bOverwrite,
            /* [retval][out] */ VARIANT_BOOL *pbValue) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryFileVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryFile * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryFile * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryFile * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ILibraryFile * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ILibraryFile * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ILibraryFile * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ILibraryFile * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Path)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Path )( 
            ILibraryFile * This,
            /* [retval][out] */ BSTR *psPath);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            ILibraryFile * This,
            /* [retval][out] */ BSTR *psName);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Size)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            ILibraryFile * This,
            /* [retval][out] */ ULONGLONG *pnSize);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_URN)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_URN )( 
            ILibraryFile * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ BSTR *psURN);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Hash)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Hash )( 
            ILibraryFile * This,
            /* [in] */ URN_TYPE nType,
            /* [in] */ ENCODING nEncoding,
            /* [retval][out] */ BSTR *psURN);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_URL)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_URL )( 
            ILibraryFile * This,
            /* [retval][out] */ BSTR *psURL);
        
        DECLSPEC_XFGVIRT(IEnvyFile, get_Magnet)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Magnet )( 
            ILibraryFile * This,
            /* [retval][out] */ BSTR *psMagnet);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ILibraryFile * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            ILibraryFile * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Folder)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Folder )( 
            ILibraryFile * This,
            /* [retval][out] */ ILibraryFolder **ppFolder);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Shared)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Shared )( 
            ILibraryFile * This,
            /* [retval][out] */ TRISTATE *pnValue);
        
        DECLSPEC_XFGVIRT(ILibraryFile, put_Shared)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Shared )( 
            ILibraryFile * This,
            /* [in] */ TRISTATE nValue);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_EffectiveShared)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_EffectiveShared )( 
            ILibraryFile * This,
            /* [retval][out] */ VARIANT_BOOL *pbValue);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Index)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Index )( 
            ILibraryFile * This,
            /* [retval][out] */ LONG *pnIndex);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_MetadataAuto)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_MetadataAuto )( 
            ILibraryFile * This,
            /* [retval][out] */ VARIANT_BOOL *pbValue);
        
        DECLSPEC_XFGVIRT(ILibraryFile, get_Metadata)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Metadata )( 
            ILibraryFile * This,
            /* [retval][out] */ ISXMLElement **ppXML);
        
        DECLSPEC_XFGVIRT(ILibraryFile, put_Metadata)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Metadata )( 
            ILibraryFile * This,
            /* [in] */ ISXMLElement *pXML);
        
        DECLSPEC_XFGVIRT(ILibraryFile, Execute)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Execute )( 
            ILibraryFile * This);
        
        DECLSPEC_XFGVIRT(ILibraryFile, Delete)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Delete )( 
            ILibraryFile * This);
        
        DECLSPEC_XFGVIRT(ILibraryFile, Rename)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Rename )( 
            ILibraryFile * This,
            /* [in] */ BSTR sNewName);
        
        DECLSPEC_XFGVIRT(ILibraryFile, Copy)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Copy )( 
            ILibraryFile * This,
            /* [in] */ BSTR sNewPath);
        
        DECLSPEC_XFGVIRT(ILibraryFile, Move)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Move )( 
            ILibraryFile * This,
            /* [in] */ BSTR sNewPath);
        
        DECLSPEC_XFGVIRT(ILibraryFile, MergeMetadata)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *MergeMetadata )( 
            ILibraryFile * This,
            /* [in] */ ISXMLElement *pXML,
            /* [in] */ VARIANT_BOOL bOverwrite,
            /* [retval][out] */ VARIANT_BOOL *pbValue);
        
        END_INTERFACE
    } ILibraryFileVtbl;

    interface ILibraryFile
    {
        CONST_VTBL struct ILibraryFileVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryFile_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryFile_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryFile_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryFile_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ILibraryFile_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ILibraryFile_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ILibraryFile_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ILibraryFile_get_Path(This,psPath)	\
    ( (This)->lpVtbl -> get_Path(This,psPath) ) 

#define ILibraryFile_get_Name(This,psName)	\
    ( (This)->lpVtbl -> get_Name(This,psName) ) 

#define ILibraryFile_get_Size(This,pnSize)	\
    ( (This)->lpVtbl -> get_Size(This,pnSize) ) 

#define ILibraryFile_get_URN(This,sURN,psURN)	\
    ( (This)->lpVtbl -> get_URN(This,sURN,psURN) ) 

#define ILibraryFile_get_Hash(This,nType,nEncoding,psURN)	\
    ( (This)->lpVtbl -> get_Hash(This,nType,nEncoding,psURN) ) 

#define ILibraryFile_get_URL(This,psURL)	\
    ( (This)->lpVtbl -> get_URL(This,psURL) ) 

#define ILibraryFile_get_Magnet(This,psMagnet)	\
    ( (This)->lpVtbl -> get_Magnet(This,psMagnet) ) 


#define ILibraryFile_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ILibraryFile_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define ILibraryFile_get_Folder(This,ppFolder)	\
    ( (This)->lpVtbl -> get_Folder(This,ppFolder) ) 

#define ILibraryFile_get_Shared(This,pnValue)	\
    ( (This)->lpVtbl -> get_Shared(This,pnValue) ) 

#define ILibraryFile_put_Shared(This,nValue)	\
    ( (This)->lpVtbl -> put_Shared(This,nValue) ) 

#define ILibraryFile_get_EffectiveShared(This,pbValue)	\
    ( (This)->lpVtbl -> get_EffectiveShared(This,pbValue) ) 

#define ILibraryFile_get_Index(This,pnIndex)	\
    ( (This)->lpVtbl -> get_Index(This,pnIndex) ) 

#define ILibraryFile_get_MetadataAuto(This,pbValue)	\
    ( (This)->lpVtbl -> get_MetadataAuto(This,pbValue) ) 

#define ILibraryFile_get_Metadata(This,ppXML)	\
    ( (This)->lpVtbl -> get_Metadata(This,ppXML) ) 

#define ILibraryFile_put_Metadata(This,pXML)	\
    ( (This)->lpVtbl -> put_Metadata(This,pXML) ) 

#define ILibraryFile_Execute(This)	\
    ( (This)->lpVtbl -> Execute(This) ) 

#define ILibraryFile_Delete(This)	\
    ( (This)->lpVtbl -> Delete(This) ) 

#define ILibraryFile_Rename(This,sNewName)	\
    ( (This)->lpVtbl -> Rename(This,sNewName) ) 

#define ILibraryFile_Copy(This,sNewPath)	\
    ( (This)->lpVtbl -> Copy(This,sNewPath) ) 

#define ILibraryFile_Move(This,sNewPath)	\
    ( (This)->lpVtbl -> Move(This,sNewPath) ) 

#define ILibraryFile_MergeMetadata(This,pXML,bOverwrite,pbValue)	\
    ( (This)->lpVtbl -> MergeMetadata(This,pXML,bOverwrite,pbValue) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryFile_INTERFACE_DEFINED__ */


#ifndef __ILibraryFiles_INTERFACE_DEFINED__
#define __ILibraryFiles_INTERFACE_DEFINED__

/* interface ILibraryFiles */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ILibraryFiles;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("49346C06-DC33-4975-978E-E807F7E41EF9")
    ILibraryFiles : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ILibraryFile **ppFile) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryFilesVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryFiles * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryFiles * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryFiles * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ILibraryFiles * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ILibraryFiles * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ILibraryFiles * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ILibraryFiles * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ILibraryFiles, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ILibraryFiles * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ILibraryFiles, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            ILibraryFiles * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(ILibraryFiles, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ILibraryFiles * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ILibraryFiles, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ILibraryFiles * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ILibraryFile **ppFile);
        
        DECLSPEC_XFGVIRT(ILibraryFiles, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ILibraryFiles * This,
            /* [retval][out] */ LONG *pnCount);
        
        END_INTERFACE
    } ILibraryFilesVtbl;

    interface ILibraryFiles
    {
        CONST_VTBL struct ILibraryFilesVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryFiles_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryFiles_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryFiles_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryFiles_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ILibraryFiles_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ILibraryFiles_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ILibraryFiles_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ILibraryFiles_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ILibraryFiles_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define ILibraryFiles_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ILibraryFiles_get_Item(This,vIndex,ppFile)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppFile) ) 

#define ILibraryFiles_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryFiles_INTERFACE_DEFINED__ */


#ifndef __ILibraryFolder_INTERFACE_DEFINED__
#define __ILibraryFolder_INTERFACE_DEFINED__

/* interface ILibraryFolder */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ILibraryFolder;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8A6BC680-3451-4a78-8A01-B7DFC1D9A148")
    ILibraryFolder : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Parent( 
            /* [retval][out] */ ILibraryFolder **ppFolder) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Path( 
            /* [retval][out] */ BSTR *psPath) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Name( 
            /* [retval][out] */ BSTR *psPath) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Shared( 
            /* [retval][out] */ TRISTATE *pnValue) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_Shared( 
            /* [in] */ TRISTATE nValue) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_EffectiveShared( 
            /* [retval][out] */ VARIANT_BOOL *pbValue) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Folders( 
            /* [retval][out] */ ILibraryFolders **ppFolders) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Files( 
            /* [retval][out] */ ILibraryFiles **ppFiles) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryFolderVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryFolder * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryFolder * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryFolder * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ILibraryFolder * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ILibraryFolder * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ILibraryFolder * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ILibraryFolder * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ILibraryFolder * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            ILibraryFolder * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Parent)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Parent )( 
            ILibraryFolder * This,
            /* [retval][out] */ ILibraryFolder **ppFolder);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Path)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Path )( 
            ILibraryFolder * This,
            /* [retval][out] */ BSTR *psPath);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Name)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Name )( 
            ILibraryFolder * This,
            /* [retval][out] */ BSTR *psPath);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Shared)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Shared )( 
            ILibraryFolder * This,
            /* [retval][out] */ TRISTATE *pnValue);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, put_Shared)
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_Shared )( 
            ILibraryFolder * This,
            /* [in] */ TRISTATE nValue);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_EffectiveShared)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_EffectiveShared )( 
            ILibraryFolder * This,
            /* [retval][out] */ VARIANT_BOOL *pbValue);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Folders)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Folders )( 
            ILibraryFolder * This,
            /* [retval][out] */ ILibraryFolders **ppFolders);
        
        DECLSPEC_XFGVIRT(ILibraryFolder, get_Files)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Files )( 
            ILibraryFolder * This,
            /* [retval][out] */ ILibraryFiles **ppFiles);
        
        END_INTERFACE
    } ILibraryFolderVtbl;

    interface ILibraryFolder
    {
        CONST_VTBL struct ILibraryFolderVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryFolder_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryFolder_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryFolder_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryFolder_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ILibraryFolder_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ILibraryFolder_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ILibraryFolder_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ILibraryFolder_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ILibraryFolder_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define ILibraryFolder_get_Parent(This,ppFolder)	\
    ( (This)->lpVtbl -> get_Parent(This,ppFolder) ) 

#define ILibraryFolder_get_Path(This,psPath)	\
    ( (This)->lpVtbl -> get_Path(This,psPath) ) 

#define ILibraryFolder_get_Name(This,psPath)	\
    ( (This)->lpVtbl -> get_Name(This,psPath) ) 

#define ILibraryFolder_get_Shared(This,pnValue)	\
    ( (This)->lpVtbl -> get_Shared(This,pnValue) ) 

#define ILibraryFolder_put_Shared(This,nValue)	\
    ( (This)->lpVtbl -> put_Shared(This,nValue) ) 

#define ILibraryFolder_get_EffectiveShared(This,pbValue)	\
    ( (This)->lpVtbl -> get_EffectiveShared(This,pbValue) ) 

#define ILibraryFolder_get_Folders(This,ppFolders)	\
    ( (This)->lpVtbl -> get_Folders(This,ppFolders) ) 

#define ILibraryFolder_get_Files(This,ppFiles)	\
    ( (This)->lpVtbl -> get_Files(This,ppFiles) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryFolder_INTERFACE_DEFINED__ */


#ifndef __ILibraryFolders_INTERFACE_DEFINED__
#define __ILibraryFolders_INTERFACE_DEFINED__

/* interface ILibraryFolders */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ILibraryFolders;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("43DF8D22-6F85-4d0a-B072-1C8BF8A57073")
    ILibraryFolders : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Library( 
            /* [retval][out] */ ILibrary **ppLibrary) = 0;
        
        virtual /* [restricted][propget][id] */ HRESULT STDMETHODCALLTYPE get__NewEnum( 
            /* [retval][out] */ IUnknown **ppEnum) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Item( 
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ILibraryFolder **ppFolder) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Count( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryFoldersVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryFolders * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryFolders * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryFolders * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ILibraryFolders * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ILibraryFolders * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ILibraryFolders * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ILibraryFolders * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ILibraryFolders, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ILibraryFolders * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ILibraryFolders, get_Library)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Library )( 
            ILibraryFolders * This,
            /* [retval][out] */ ILibrary **ppLibrary);
        
        DECLSPEC_XFGVIRT(ILibraryFolders, get__NewEnum)
        /* [restricted][propget][id] */ HRESULT ( STDMETHODCALLTYPE *get__NewEnum )( 
            ILibraryFolders * This,
            /* [retval][out] */ IUnknown **ppEnum);
        
        DECLSPEC_XFGVIRT(ILibraryFolders, get_Item)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Item )( 
            ILibraryFolders * This,
            /* [in] */ VARIANT vIndex,
            /* [retval][out] */ ILibraryFolder **ppFolder);
        
        DECLSPEC_XFGVIRT(ILibraryFolders, get_Count)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Count )( 
            ILibraryFolders * This,
            /* [retval][out] */ LONG *pnCount);
        
        END_INTERFACE
    } ILibraryFoldersVtbl;

    interface ILibraryFolders
    {
        CONST_VTBL struct ILibraryFoldersVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryFolders_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryFolders_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryFolders_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryFolders_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ILibraryFolders_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ILibraryFolders_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ILibraryFolders_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ILibraryFolders_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ILibraryFolders_get_Library(This,ppLibrary)	\
    ( (This)->lpVtbl -> get_Library(This,ppLibrary) ) 

#define ILibraryFolders_get__NewEnum(This,ppEnum)	\
    ( (This)->lpVtbl -> get__NewEnum(This,ppEnum) ) 

#define ILibraryFolders_get_Item(This,vIndex,ppFolder)	\
    ( (This)->lpVtbl -> get_Item(This,vIndex,ppFolder) ) 

#define ILibraryFolders_get_Count(This,pnCount)	\
    ( (This)->lpVtbl -> get_Count(This,pnCount) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryFolders_INTERFACE_DEFINED__ */


#ifndef __ILibraryPlugin_INTERFACE_DEFINED__
#define __ILibraryPlugin_INTERFACE_DEFINED__

/* interface ILibraryPlugin */
/* [object][oleautomation][uuid] */ 


EXTERN_C const IID IID_ILibraryPlugin;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("8065EF37-F0EA-4898-BBBD-D37798DE83CC")
    ILibraryPlugin : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE OnNewFile( 
            /* [in] */ ILibraryFile *pFile) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ILibraryPluginVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ILibraryPlugin * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ILibraryPlugin * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ILibraryPlugin * This);
        
        DECLSPEC_XFGVIRT(ILibraryPlugin, OnNewFile)
        HRESULT ( STDMETHODCALLTYPE *OnNewFile )( 
            ILibraryPlugin * This,
            /* [in] */ ILibraryFile *pFile);
        
        END_INTERFACE
    } ILibraryPluginVtbl;

    interface ILibraryPlugin
    {
        CONST_VTBL struct ILibraryPluginVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ILibraryPlugin_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ILibraryPlugin_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ILibraryPlugin_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ILibraryPlugin_OnNewFile(This,pFile)	\
    ( (This)->lpVtbl -> OnNewFile(This,pFile) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ILibraryPlugin_INTERFACE_DEFINED__ */


#ifndef __ICollectionHtmlView_INTERFACE_DEFINED__
#define __ICollectionHtmlView_INTERFACE_DEFINED__

/* interface ICollectionHtmlView */
/* [object][oleautomation][dual][uuid] */ 


EXTERN_C const IID IID_ICollectionHtmlView;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("CF66956E-901F-44D0-B5C6-FC6A436A030D")
    ICollectionHtmlView : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_Application( 
            /* [retval][out] */ IApplication **ppApplication) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Detect( 
            /* [in] */ BSTR sURN,
            /* [retval][out] */ BSTR *psState) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Hover( 
            /* [in] */ BSTR sURN) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Open( 
            /* [in] */ BSTR sURN,
            /* [retval][out] */ VARIANT_BOOL *pbResult) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Enqueue( 
            /* [in] */ BSTR sURN,
            /* [retval][out] */ VARIANT_BOOL *pbResult) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Download( 
            /* [in] */ BSTR sMagnet,
            /* [retval][out] */ VARIANT_BOOL *pbResult) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE DownloadAll( void) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_MissingCount( 
            /* [retval][out] */ LONG *pnCount) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct ICollectionHtmlViewVtbl
    {
        BEGIN_INTERFACE
        
        DECLSPEC_XFGVIRT(IUnknown, QueryInterface)
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICollectionHtmlView * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        DECLSPEC_XFGVIRT(IUnknown, AddRef)
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICollectionHtmlView * This);
        
        DECLSPEC_XFGVIRT(IUnknown, Release)
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICollectionHtmlView * This);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfoCount)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            ICollectionHtmlView * This,
            /* [out] */ UINT *pctinfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetTypeInfo)
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            ICollectionHtmlView * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        DECLSPEC_XFGVIRT(IDispatch, GetIDsOfNames)
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            ICollectionHtmlView * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        DECLSPEC_XFGVIRT(IDispatch, Invoke)
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            ICollectionHtmlView * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, get_Application)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_Application )( 
            ICollectionHtmlView * This,
            /* [retval][out] */ IApplication **ppApplication);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, Detect)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Detect )( 
            ICollectionHtmlView * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ BSTR *psState);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, Hover)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Hover )( 
            ICollectionHtmlView * This,
            /* [in] */ BSTR sURN);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, Open)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Open )( 
            ICollectionHtmlView * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, Enqueue)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Enqueue )( 
            ICollectionHtmlView * This,
            /* [in] */ BSTR sURN,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, Download)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Download )( 
            ICollectionHtmlView * This,
            /* [in] */ BSTR sMagnet,
            /* [retval][out] */ VARIANT_BOOL *pbResult);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, DownloadAll)
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *DownloadAll )( 
            ICollectionHtmlView * This);
        
        DECLSPEC_XFGVIRT(ICollectionHtmlView, get_MissingCount)
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_MissingCount )( 
            ICollectionHtmlView * This,
            /* [retval][out] */ LONG *pnCount);
        
        END_INTERFACE
    } ICollectionHtmlViewVtbl;

    interface ICollectionHtmlView
    {
        CONST_VTBL struct ICollectionHtmlViewVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define ICollectionHtmlView_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define ICollectionHtmlView_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define ICollectionHtmlView_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define ICollectionHtmlView_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define ICollectionHtmlView_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define ICollectionHtmlView_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define ICollectionHtmlView_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define ICollectionHtmlView_get_Application(This,ppApplication)	\
    ( (This)->lpVtbl -> get_Application(This,ppApplication) ) 

#define ICollectionHtmlView_Detect(This,sURN,psState)	\
    ( (This)->lpVtbl -> Detect(This,sURN,psState) ) 

#define ICollectionHtmlView_Hover(This,sURN)	\
    ( (This)->lpVtbl -> Hover(This,sURN) ) 

#define ICollectionHtmlView_Open(This,sURN,pbResult)	\
    ( (This)->lpVtbl -> Open(This,sURN,pbResult) ) 

#define ICollectionHtmlView_Enqueue(This,sURN,pbResult)	\
    ( (This)->lpVtbl -> Enqueue(This,sURN,pbResult) ) 

#define ICollectionHtmlView_Download(This,sMagnet,pbResult)	\
    ( (This)->lpVtbl -> Download(This,sMagnet,pbResult) ) 

#define ICollectionHtmlView_DownloadAll(This)	\
    ( (This)->lpVtbl -> DownloadAll(This) ) 

#define ICollectionHtmlView_get_MissingCount(This,pnCount)	\
    ( (This)->lpVtbl -> get_MissingCount(This,pnCount) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __ICollectionHtmlView_INTERFACE_DEFINED__ */


EXTERN_C const CLSID CLSID_EnvyApplication;

#ifdef __cplusplus

class DECLSPEC_UUID("E9B2EF9B-4A0C-451e-801F-257861B87FAD")
EnvyApplication;
#endif

EXTERN_C const CLSID CLSID_EnvyXML;

#ifdef __cplusplus

class DECLSPEC_UUID("30FC662A-D72A-4f79-B63A-ACD4FBFE68A3")
EnvyXML;
#endif

EXTERN_C const CLSID CLSID_EnvyXMLCollection;

#ifdef __cplusplus

class DECLSPEC_UUID("D73ABD28-3A2A-4e36-AD6F-2AA8F011FBE3")
EnvyXMLCollection;
#endif

EXTERN_C const CLSID CLSID_EnvyDataSource;

#ifdef __cplusplus

class DECLSPEC_UUID("34791E02-51DC-4CF4-9E34-018166D91D0E")
EnvyDataSource;
#endif

EXTERN_C const CLSID CLSID_EnvyIEProtocol;

#ifdef __cplusplus

class DECLSPEC_UUID("18D11ED9-1264-48A1-9E14-20F2C633242B")
EnvyIEProtocol;
#endif

EXTERN_C const CLSID CLSID_EnvyIEProtocolRequest;

#ifdef __cplusplus

class DECLSPEC_UUID("E1A67AE5-7041-4AE1-94F7-DE03EF759E27")
EnvyIEProtocolRequest;
#endif
#endif /* __Envy_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


