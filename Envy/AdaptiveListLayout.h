//
// AdaptiveListLayout.h
//
// MFC helper: apply AdaptiveAllocateColumns to a CListCtrl without
// registry writes or resize feedback loops.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "AdaptiveListColumns.h"

class CListCtrl;
class CWnd;

struct AdaptiveStickyNotifyContext
{
	CListCtrl& wndList;
	UINT nListId;
	BOOL bApplying;
	int nColCount;
	BOOL* pSticky;
	int* pStickyWidth;
};

// nScalePercent: Settings.Interface.DisplayScaling (100-200).
// pSticky / pStickyWidth: optional per-column user overrides (length nCount).
// pbApplying: set TRUE for the duration of SetColumnWidth calls so callers
// can ignore HDN_ENDTRACK / HDN_ITEMCHANGED sticky capture.
BOOL AdaptiveApplyListColumns(
    CListCtrl& wndList,
    AdaptiveColumnSpec* pSpecs,
    int nCount,
    int nScalePercent,
    const BOOL* pSticky,
    const int* pStickyWidth,
    BOOL* pbApplying);

// Capture user column resize from list-header HDN_ENDTRACK / HDN_ITEMCHANGED.
// Call from the panel OnNotify before forwarding to the base class.
// The header sends HDN_* to the list, not the panel; list OnNotify must relay.
// LVN_COLUMNWIDTHCHANGED is not an SDK CommCtrl constant (MSVC C2065).
void AdaptiveCaptureStickyColumnFromHeaderNotify(
    const AdaptiveStickyNotifyContext& ctx,
    WPARAM wParam,
    LPARAM lParam);

// Relay list-header HDN_* to the parent so panel OnNotify can record sticky.
void AdaptiveRelayHeaderNotifyToParent(const CWnd& wndList, WPARAM wParam, LPARAM lParam);

// Persist / restore sticky mask under ListStates (separate from Widths hex).
void AdaptiveSaveStickyColumnState(
    LPCTSTR pszName,
    int nColCount,
    const BOOL* pSticky);

BOOL AdaptiveLoadStickyColumnState(
    LPCTSTR pszName,
    int nColCount,
    BOOL* pSticky,
    int* pStickyWidth,
    CListCtrl& wndList);

// Before SaveList: write preferred widths for non-sticky columns so allocator
// fill is not persisted as fake user intent (architecture option a).
void AdaptiveNormalizeNonStickyForSave(
    CListCtrl& wndList,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int nScalePercent,
    const BOOL* pSticky,
    BOOL* pbApplying);
