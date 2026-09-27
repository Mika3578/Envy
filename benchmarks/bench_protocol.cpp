//
// bench_protocol.cpp
//
// Pure production framing helpers from Envy/PacketLengthValidate.h.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include "bench_harness.h"

#include "../Envy/PacketLengthValidate.h"

#include <cstdint>
#include <vector>

namespace
{

volatile std::uint32_t g_protocol_sink = 0;

std::uint64_t BenchBtLengths(std::size_t batch)
{
	std::uint32_t acc = 0;
	const DWORD lengths[] = { 0, 1, 2, 4, 1024, BT_PACKET_LENGTH_MAX, BT_PACKET_LENGTH_MAX + 1 };
	for (std::size_t i = 0; i < batch; ++i)
	{
		const DWORD n = lengths[i % (sizeof(lengths) / sizeof(lengths[0]))];
		acc += BtPacketLengthOk(n) ? 1u : 0u;
		acc += BtIsKeepAliveLength(n) ? 2u : 0u;
		acc += BtExtensionPayloadLengthOk(n) ? 4u : 0u;
	}
	g_protocol_sink = acc;
	return acc;
}

std::uint64_t BenchEd2kLengths(std::size_t batch)
{
	std::uint32_t acc = 0;
	for (std::size_t i = 0; i < batch; ++i)
	{
		const DWORD body = static_cast<DWORD>(1 + (i % 4096));
		acc += Ed2kTcpPacketLengthOk(512, 5, body) ? 1u : 0u;
		acc += Ed2kPreviewFrameAcceptable(128, 256) ? 2u : 0u;
	}
	g_protocol_sink = acc;
	return acc;
}

std::uint64_t BenchG1Lengths(std::size_t batch)
{
	std::uint32_t acc = 0;
	const DWORD max_total = 256 * 1024;
	for (std::size_t i = 0; i < batch; ++i)
	{
		const LONG payload = static_cast<LONG>(1000 + (i % 5000));
		acc += G1PacketTotalLengthOk(payload, max_total) ? 1u : 0u;
		acc += G1QueryHitXmlFits(100, 200) ? 2u : 0u;
	}
	g_protocol_sink = acc;
	return acc;
}

std::uint64_t BenchG2Lengths(std::size_t batch)
{
	std::uint32_t acc = 0;
	for (std::size_t i = 0; i < batch; ++i)
	{
		const DWORD body = 50 + static_cast<DWORD>(i % 100);
		acc += G2FrameLengthFits(64, body, 1, 3) ? 1u : 0u;
		acc += G2SubpacketPayloadFits(200, body, 4) ? 2u : 0u;
	}
	g_protocol_sink = acc;
	return acc;
}

void RegisterProtocol(BenchRegistry& registry,
                      const char* name,
                      BenchWorkloadFn fn,
                      std::uint64_t batch,
                      std::uint64_t ops)
{
	BenchRegistry::Entry e{};
	e.group = "protocol";
	e.name = name;
	e.workload = std::move(fn);
	e.warmup_samples = 2;
	e.timed_samples = 7;
	e.iterations_per_sample = 1;
	e.bytes_per_iteration = 0;
	e.ops_per_iteration = ops;
	registry.Register(std::move(e));
}

} // namespace

void BenchRegisterProtocolWorkloads(BenchRegistry& registry)
{
	const std::uint64_t batch = 500000;
	RegisterProtocol(registry, "bt/length", [batch]()
	                 { return BenchBtLengths(batch); }, batch, batch * 3);
	RegisterProtocol(registry, "ed2k/length", [batch]()
	                 { return BenchEd2kLengths(batch); }, batch, batch * 2);
	RegisterProtocol(registry, "g1/length", [batch]()
	                 { return BenchG1Lengths(batch); }, batch, batch * 2);
	RegisterProtocol(registry, "g2/frame", [batch]()
	                 { return BenchG2Lengths(batch); }, batch, batch * 2);
}
