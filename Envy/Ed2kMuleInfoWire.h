//
// Ed2kMuleInfoWire.h
//
// Pure wire constants for the legacy eMule MuleInfo header. The historical
// version byte and the compatible-client identity are distinct protocol fields
// even though Envy currently uses 0x50 for both values.
//
// eMule 0.50b emits 0x50 from its legacy short-version field. Current aMule
// keeps a separate fixed CURRENT_VERSION_SHORT (0x47). Envy's 4.x application
// version must not be packed into the old eMule 0.xx convention.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include <cstdint>

constexpr uint8_t ED2K_MULEINFO_LEGACY_VERSION = 0x50u;
constexpr uint8_t ED2K_MULEINFO_PROTOCOL = 0x01u;

struct Ed2kMuleInfoIdentity
{
	uint8_t legacyVersion;
	uint8_t protocol;
	uint8_t compatibleClient;
};

inline constexpr Ed2kMuleInfoIdentity Ed2kMakeMuleInfoIdentity(
    uint8_t compatibleClient) noexcept
{
	return {
		ED2K_MULEINFO_LEGACY_VERSION,
		ED2K_MULEINFO_PROTOCOL,
		compatibleClient
	};
}
