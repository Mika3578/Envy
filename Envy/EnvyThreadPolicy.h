//
// EnvyThreadPolicy.h
//
// Shutdown policy for CEnvyThread::CloseThread (#92).
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

// When a worker does not exit after cooperative cancel + wait timeout,
// Envy must not call TerminateThread (orphans locks / TLS). Tracking is
// abandoned and the OS thread is left to exit on its own.
inline constexpr bool EnvyThreadAllowForcedTerminate()
{
	return false;
}
