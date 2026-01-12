

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for GFLImageServices.idl:
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


#ifndef __GFLImageServices_h__
#define __GFLImageServices_h__

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

#ifndef __GFLReader_FWD_DEFINED__
#define __GFLReader_FWD_DEFINED__

#ifdef __cplusplus
typedef class GFLReader GFLReader;
#else
typedef struct GFLReader GFLReader;
#endif /* __cplusplus */

#endif 	/* __GFLReader_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"
#include "Envy.h"

#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __GFLImageServicesLib_LIBRARY_DEFINED__
#define __GFLImageServicesLib_LIBRARY_DEFINED__

/* library GFLImageServicesLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_GFLImageServicesLib;

EXTERN_C const CLSID CLSID_GFLReader;

#ifdef __cplusplus

class DECLSPEC_UUID("C9314782-CB91-40B8-B375-F631FF30C1C8")
GFLReader;
#endif
#endif /* __GFLImageServicesLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


