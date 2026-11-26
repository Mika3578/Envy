//
// Ed2kMuleInfoWire.h
//
// Legacy eMuleInfo prefix used by both EMULEINFO and EMULEINFOANSWER.
// The historical short version is not the compatible-client ID carried
// separately by the ET_COMPATIBLECLIENT tag or modern Hello.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//
// Envy is free software. You may redistribute and/or modify it
// under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation (fsf.org);
// version 3 or later at your option. (AGPLv3)
//

#pragma once

#include <cstddef>
#include <cstdint>

struct Ed2kMuleInfoWirePrefix
{
	std::uint8_t legacyVersion;
	std::uint8_t protocolVersion;
};

// Preserve the historical 0x50 version byte and 0x01 eMule protocol byte.
// A different Envy software/compatible-client ID must not silently alter
// the legacy MuleInfo version field.
constexpr Ed2kMuleInfoWirePrefix Ed2kLegacyMuleInfoWirePrefix() noexcept
{
	return { 0x50u, 0x01u };
}

// Two-byte legacy prefix written by SendEmuleInfo for EMULEINFO / EMULEINFOANSWER.
inline void PackEd2kLegacyMuleInfoPrefix(std::uint8_t* pBytes) noexcept
{
	const Ed2kMuleInfoWirePrefix oPrefix = Ed2kLegacyMuleInfoWirePrefix();
	pBytes[0] = oPrefix.legacyVersion;
	pBytes[1] = oPrefix.protocolVersion;
}
