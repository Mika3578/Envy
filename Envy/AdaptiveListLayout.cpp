//
// AdaptiveListLayout.cpp
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#include "StdAfx.h"
#include "AdaptiveListLayout.h"
#include "Registry.h"

#include <array>

BOOL AdaptiveApplyListColumns(
    CListCtrl& wndList,
    AdaptiveColumnSpec* pSpecs,
    int nCount,
    int nScalePercent,
    const BOOL* pSticky,
    const int* pStickyWidth,
    BOOL* pbApplying)
{
	if (!::IsWindow(wndList.GetSafeHwnd()) || !pSpecs || nCount <= 0)
		return FALSE;

	if (pSticky && pStickyWidth)
	{
		for (int i = 0; i < nCount; ++i)
		{
			pSpecs[i].bSticky = pSticky[i];
			pSpecs[i].nStickyWidth = pStickyWidth[i];
		}
	}

	CRect rc;
	wndList.GetClientRect(&rc);
	int nWidth = rc.Width();
	if (nWidth > 0)
	{
		// Match LiveListSizer: leave room for the vertical scrollbar gutter.
		nWidth -= GetSystemMetrics(SM_CXVSCROLL) - 1;
		if (nWidth < 0)
			nWidth = 0;
	}

	std::array<int, 32> nOut{};
	if (nCount > 32)
		return FALSE;

	if (!AdaptiveAllocateColumns(nWidth, nScalePercent, pSpecs, nCount, nOut.data()))
		return FALSE;

	if (pbApplying)
		*pbApplying = TRUE;

	for (int i = 0; i < nCount; ++i)
	{
		if (wndList.GetColumnWidth(i) != nOut[i])
			wndList.SetColumnWidth(i, nOut[i]);
	}

	if (pbApplying)
		*pbApplying = FALSE;

	return TRUE;
}

void AdaptiveCaptureStickyColumnFromHeaderNotify(
    const AdaptiveStickyNotifyContext& ctx,
    WPARAM wParam,
    LPARAM lParam)
{
	const auto* pNMHDR = (const NMHDR*)lParam;
	if (!pNMHDR || ctx.bApplying || !ctx.pSticky || !ctx.pStickyWidth || ctx.nColCount <= 0)
		return;

	// Report-list headers often use control ID 0; accept hwndFrom == header.
	const CHeaderCtrl* pHeader = ctx.wndList.GetHeaderCtrl();
	if (const BOOL bFromHeader =
	        (pHeader && pNMHDR->hwndFrom == pHeader->GetSafeHwnd());
	    !bFromHeader && wParam != ctx.nListId && pNMHDR->idFrom != ctx.nListId)
	{
		return;
	}

	if (pNMHDR->code != HDN_ENDTRACK && pNMHDR->code != HDN_ENDTRACKW &&
	    pNMHDR->code != HDN_ITEMCHANGED && pNMHDR->code != HDN_ITEMCHANGEDW)
		return;

	const auto* pHDR = (const NMHEADER*)pNMHDR;
	const int nCol = pHDR->iItem;
	if (nCol < 0 || nCol >= ctx.nColCount)
		return;

	if (pNMHDR->code != HDN_ENDTRACK && pNMHDR->code != HDN_ENDTRACKW &&
	    !(pHDR->pitem && (pHDR->pitem->mask & HDI_WIDTH)))
		return;

	// HDN_ENDTRACK may fire before the list control commits the drag; prefer
	// NMHEADER::pitem->cxy when HDI_WIDTH is present, else fall back to query.
	int nWidth = ctx.wndList.GetColumnWidth(nCol);
	if (pHDR->pitem && (pHDR->pitem->mask & HDI_WIDTH) && pHDR->pitem->cxy >= 0)
		nWidth = pHDR->pitem->cxy;

	ctx.pSticky[nCol] = TRUE;
	ctx.pStickyWidth[nCol] = nWidth;
}

void AdaptiveRelayHeaderNotifyToParent(const CWnd& wndList, WPARAM wParam, LPARAM lParam)
{
	const auto* pNMHDR = (const NMHDR*)lParam;
	if (!pNMHDR)
		return;
	if (pNMHDR->code != HDN_ENDTRACK && pNMHDR->code != HDN_ENDTRACKW &&
	    pNMHDR->code != HDN_ITEMCHANGED && pNMHDR->code != HDN_ITEMCHANGEDW)
		return;

	const CWnd* pParent = wndList.GetParent();
	const HWND hParent = pParent ? pParent->GetSafeHwnd() : nullptr;
	if (hParent)
		::SendMessage(hParent, WM_NOTIFY, wParam, lParam);
}

void AdaptiveSaveStickyColumnState(
    LPCTSTR pszName,
    int nColCount,
    const BOOL* pSticky)
{
	if (!pszName || !pSticky || nColCount <= 0 || nColCount > 32)
		return;

	DWORD dwMask = 0;
	for (int i = 0; i < nColCount; ++i)
	{
		if (pSticky[i])
			dwMask |= (1u << i);
	}

	CString strItem;
	strItem.Format(L"%s.Sticky", pszName);
	CRegistry::SetInt(L"ListStates", strItem, (int)dwMask);
}

BOOL AdaptiveLoadStickyColumnState(
    LPCTSTR pszName,
    int nColCount,
    BOOL* pSticky,
    int* pStickyWidth,
    CListCtrl& wndList)
{
	if (!pszName || !pSticky || !pStickyWidth || nColCount <= 0 || nColCount > 32)
		return FALSE;
	if (!::IsWindow(wndList.GetSafeHwnd()))
		return FALSE;

	ZeroMemory(pSticky, sizeof(BOOL) * nColCount);
	ZeroMemory(pStickyWidth, sizeof(int) * nColCount);

	CString strItem;
	strItem.Format(L"%s.Sticky", pszName);
	const auto dwMask = static_cast<DWORD>(CRegistry::GetInt(L"ListStates", strItem, 0));

	BOOL bAny = FALSE;
	for (int i = 0; i < nColCount; ++i)
	{
		if (dwMask & (1u << i))
		{
			pSticky[i] = TRUE;
			pStickyWidth[i] = wndList.GetColumnWidth(i);
			bAny = TRUE;
		}
	}
	return bAny;
}

void AdaptiveNormalizeNonStickyForSave(
    CListCtrl& wndList,
    const AdaptiveColumnSpec* pSpecs,
    int nCount,
    int nScalePercent,
    const BOOL* pSticky,
    BOOL* pbApplying)
{
	if (!::IsWindow(wndList.GetSafeHwnd()) || !pSpecs || !pSticky || nCount <= 0)
		return;

	if (pbApplying)
		*pbApplying = TRUE;

	for (int i = 0; i < nCount; ++i)
	{
		if (pSticky[i] || pSpecs[i].bHidden)
			continue;
		const int nPref = AdaptiveScalePx(pSpecs[i].nPreferred, nScalePercent);
		if (wndList.GetColumnWidth(i) != nPref)
			wndList.SetColumnWidth(i, nPref);
	}

	if (pbApplying)
		*pbApplying = FALSE;
}
