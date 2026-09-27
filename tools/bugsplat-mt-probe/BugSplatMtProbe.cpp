// Minimal link probe for BugSplat static libraries vs ENVY CRT settings.
// Does not post crashes; exits immediately after constructing BugSplat.

#include "BugSplat.h"

int wmain()
{
	// Placeholder database/app names — replace only for manual runtime crash tests.
	static BugSplat reporter(L"envy-mt-probe", L"BugSplatMtProbe", L"0.0.0");
	reporter.SetQuietMode(true);
	return 0;
}
