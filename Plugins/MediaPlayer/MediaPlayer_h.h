

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 04:14:07 2038
 */
/* Compiler settings for MediaPlayer.idl:
    Oicf, W2, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
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


#ifndef __MediaPlayer_h_h__
#define __MediaPlayer_h_h__

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

#ifndef __MediaPlayer_FWD_DEFINED__
#define __MediaPlayer_FWD_DEFINED__

#ifdef __cplusplus
typedef class MediaPlayer MediaPlayer;
#else
typedef struct MediaPlayer MediaPlayer;
#endif /* __cplusplus */

#endif 	/* __MediaPlayer_FWD_DEFINED__ */


/* header files for imported files */
#include "oaidl.h"
#include "ocidl.h"
#include "strmif.h"
#include "control.h"
#include "Envy.h"

#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __MediaPlayerLib_LIBRARY_DEFINED__
#define __MediaPlayerLib_LIBRARY_DEFINED__

/* library MediaPlayerLib */
/* [helpstring][version][uuid] */ 


EXTERN_C const IID LIBID_MediaPlayerLib;

EXTERN_C const CLSID CLSID_MediaPlayer;

#ifdef __cplusplus

class DECLSPEC_UUID("CCE7B109-15D6-4223-B6FF-0C6C851B6680")
MediaPlayer;
#endif
#endif /* __MediaPlayerLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


