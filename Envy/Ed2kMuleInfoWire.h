//
// Ed2kMuleInfoWire.h
//
// Legacy eMuleInfo prefix used by both EMULEINFO and EMULEINFOANSWER.
// The historical short version is not the compatible-client ID carried
// separately by the ET_COMPATIBLECLIENT tag or modern Hello.
//

#pragma once

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
