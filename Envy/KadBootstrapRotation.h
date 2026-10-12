//
// KadBootstrapRotation.h
//
// Bounded Kad2 bootstrap candidate rotation and per-endpoint retry policy.
// No networking or wall-clock dependencies; callers supply monotonic 32-bit ticks.
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
//

#pragma once

#include "KadRoutingTable.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

// A Kad2 bootstrap response begins with NodeID[16], TCP port[2], version[1],
// count[2], followed by count 25-byte contacts (eMule/aMule Kad2).
// aMule emits at most 20 contacts in this response. Accept trailing bytes as
// before, but never accept a truncated contact list or an unbounded count.
static constexpr uint16_t KadBootstrapMaxResponseContacts = 20;
inline bool KadBootstrapResponseLengthValid(size_t bodyBytes, uint16_t count)
{
	return count <= KadBootstrapMaxResponseContacts &&
	       bodyBytes >= 21u + static_cast<size_t>(count) * 25u;
}

class KadBootstrapRotation
{
public:
	static constexpr size_t MaxBatch = 3;
	static constexpr size_t MaxTrackedEndpoints = 2048;
	static constexpr uint32_t RequestTimeoutMs = 30000u;
	static constexpr uint32_t BackoffBaseMs = 60000u;
	static constexpr uint32_t BackoffCapMs = 600000u;

	struct Batch
	{
		std::vector<KadContact> contacts;
		size_t scanned = 0;
		size_t deferred = 0;
		size_t invalid = 0;
	};

	void Reset()
	{
		m_cursor = 0;
		m_retry.clear();
	}

	Batch Select(const std::vector<KadContact>& cache, uint32_t now)
	{
		Batch batch;
		if (cache.empty())
			return batch;

		const size_t count = cache.size();
		const size_t start = m_cursor % count;
		while (batch.scanned < count && batch.contacts.size() < MaxBatch)
		{
			const KadContact& c = cache[(start + batch.scanned) % count];
			++batch.scanned;

			if (c.ip == 0 || c.ip == 0xffffffffu || c.udpPort == 0 || KadIdIsZero(c.id))
			{
				++batch.invalid;
				continue;
			}

			const auto it = m_retry.find(Key(c.ip, c.udpPort));
			if (it != m_retry.end() && (it->second.pending || !Elapsed(now, it->second.retryAt)))
			{
				++batch.deferred;
				continue;
			}

			// The host cache is IP-indexed, but keep this safe for synthetic
			// or future lists that contain duplicate UDP endpoints.
			bool duplicate = false;
			for (const KadContact& selected : batch.contacts)
			{
				if (selected.ip == c.ip && selected.udpPort == c.udpPort)
				{
					duplicate = true;
					break;
				}
			}
			if (!duplicate)
				batch.contacts.push_back(c);
		}
		m_cursor = (start + batch.scanned) % count;
		return batch;
	}

	void Sent(uint32_t ip, uint16_t udpPort, uint32_t now)
	{
		const Key key(ip, udpPort);
		auto it = m_retry.find(key);
		if (it == m_retry.end())
		{
			if (m_retry.size() >= MaxTrackedEndpoints)
			{
				// Evict the least recently touched retry state, never grow
				// without bound when imported host caches change. Pending
				// requests must remain tracked until completion or timeout.
				auto oldest = m_retry.end();
				for (auto cur = m_retry.begin(); cur != m_retry.end(); ++cur)
				{
					if (cur->second.pending)
						continue;
					if (oldest == m_retry.end() ||
					    static_cast<uint32_t>(now - cur->second.lastTouched) >
					        static_cast<uint32_t>(now - oldest->second.lastTouched))
						oldest = cur;
				}
				if (oldest == m_retry.end())
					return;
				m_retry.erase(oldest);
			}
			it = m_retry.emplace(key, State{}).first;
		}
		it->second.pending = true;
		it->second.retryAt = now + RequestTimeoutMs + 1u;
		it->second.lastTouched = now;
	}

	bool TimedOut(uint32_t ip, uint16_t udpPort, uint32_t now)
	{
		const auto it = m_retry.find(Key(ip, udpPort));
		if (it == m_retry.end() || !it->second.pending)
			return false;
		State& state = it->second;
		state.pending = false;
		if (state.failures < 5u)
			++state.failures;
		state.retryAt = now + Delay(state.failures);
		state.lastTouched = now;
		return true;
	}

	void Accepted(uint32_t ip, uint16_t udpPort)
	{
		m_retry.erase(Key(ip, udpPort));
	}

	static uint32_t Delay(uint32_t failures)
	{
		if (failures == 0)
			return 0;
		uint32_t delay = BackoffBaseMs;
		while (--failures != 0 && delay < BackoffCapMs)
			delay = std::min(delay * 2u, BackoffCapMs);
		return delay;
	}

	static bool Elapsed(uint32_t now, uint32_t deadline)
	{
		// All deadlines are less than 2^31 ms into the future.
		return static_cast<int32_t>(now - deadline) >= 0;
	}

	size_t Tracked() const { return m_retry.size(); }

private:
	using Key = std::pair<uint32_t, uint16_t>;
	struct State
	{
		uint32_t retryAt = 0;
		uint32_t lastTouched = 0;
		uint32_t failures = 0;
		bool pending = false;
	};
	size_t m_cursor = 0;
	std::map<Key, State> m_retry;
};
