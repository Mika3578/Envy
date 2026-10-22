//
// KadBootstrapRotation.h
//
// Bounded Kad2 bootstrap candidate rotation and per-endpoint retry policy.
// No networking or wall-clock dependencies; callers supply monotonic 64-bit milliseconds.
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
// Both reference implementations emit at most 20 contacts here, but neither
// enforces that bound when reading: they consume whatever prefix of the
// announced list the datagram actually carried and keep those contacts. So the
// 20-contact bound is a local allocation cap, not a wire requirement, and an
// over-counted or short list must not cost the peer its whole answer.
// Trailing bytes stay ignored, as before.
static constexpr size_t KadBootstrapResponseHeaderBytes = 21;
static constexpr size_t KadBootstrapContactBytes = 25;
static constexpr uint16_t KadBootstrapMaxResponseContacts = 20;

// Number of contacts that may be read from a response body of bodyBytes which
// announced `announced` contacts: the framed prefix, capped at the bound above.
inline size_t KadBootstrapUsableContacts(size_t bodyBytes, uint16_t announced)
{
	if (bodyBytes < KadBootstrapResponseHeaderBytes)
		return 0;
	const size_t framed = (bodyBytes - KadBootstrapResponseHeaderBytes) / KadBootstrapContactBytes;
	return std::min({ static_cast<size_t>(announced), framed,
	                  static_cast<size_t>(KadBootstrapMaxResponseContacts) });
}

// Largest bootstrap batch that can actually be sent now: the batch bound, capped
// by the free part of the outstanding-request budget minus one slot reserved for
// other Kad traffic. Zero means the caller must not select anything. Select()
// advances the rotation cursor past every candidate it scans, so selecting more
// than can be sent would skip untried peers until the cursor wraps the cache.
inline size_t KadBootstrapBatchLimit(size_t maxBatch, size_t outstanding, size_t maxOutstanding)
{
	const size_t usable = maxOutstanding > 0 ? maxOutstanding - 1 : 0;
	const size_t free = outstanding >= usable ? 0 : usable - outstanding;
	return std::min(maxBatch, free);
}

class KadBootstrapRotation
{
public:
	static constexpr size_t MaxBatch = 3;
	// Cold start (empty routing table) runs on a much shorter cycle, so it uses
	// a smaller batch to stay at or below the reference request rate.
	static constexpr size_t MaxColdStartBatch = 2;
	static constexpr size_t MaxTrackedEndpoints = 2048;
	static constexpr uint32_t RequestTimeoutMs = 30000u;
	static constexpr uint32_t BackoffBaseMs = 60000u;
	static constexpr uint32_t BackoffCapMs = 600000u;
	// eMule/aMule accept a BOOTSTRAP_RES for 180 s after the request was sent and
	// correlate it on the sender IP alone (CPacketTracking::IsOnOutTrackList).
	static constexpr uint32_t AcceptWindowMs = 180000u;

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

	Batch Select(const std::vector<KadContact>& cache, uint64_t now, size_t maxBatch = MaxBatch)
	{
		Prune(now);
		Batch batch;
		if (cache.empty())
			return batch;

		const size_t limit = std::clamp<size_t>(maxBatch, 1u, MaxBatch);
		const size_t count = cache.size();
		const size_t start = m_cursor % count;
		while (batch.scanned < count && batch.contacts.size() < limit)
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

	bool Sent(uint32_t ip, uint16_t udpPort, uint64_t now)
	{
		Prune(now);
		const Key key(ip, udpPort);
		auto it = m_retry.find(key);
		if (it == m_retry.end())
		{
			if (m_retry.size() >= MaxTrackedEndpoints)
			{
				// Evict the least recently touched retry state, never grow
				// without bound when imported host caches change. Pending
				// requests and recent correlation/cancellation/replay history
				// must not be lost while an alternate-port reply is possible.
				auto oldest = m_retry.end();
				for (auto cur = m_retry.begin(); cur != m_retry.end(); ++cur)
				{
					if (cur->second.pending || now - cur->second.lastSent < AcceptWindowMs)
						continue;
					if (oldest == m_retry.end() ||
					    cur->second.lastTouched < oldest->second.lastTouched)
						oldest = cur;
				}
				if (oldest == m_retry.end())
					return false;
				m_retry.erase(oldest);
			}
			it = m_retry.emplace(key, State{}).first;
		}
		if (it->second.pending || (it->second.answered && now - it->second.lastSent < AcceptWindowMs))
			return false;
		it->second.answered = false;
		it->second.pending = true;
		it->second.retryAt = now + RequestTimeoutMs + 1u;
		it->second.lastTouched = now;
		it->second.lastSent = now;
		it->second.requested = true;
		return true;
	}

	// True while a BOOTSTRAP_RES from this IP may still be correlated, whatever
	// UDP source port it arrives on. A reply can legitimately come from a port
	// other than the one the contact advertised (eMule logs exactly that case
	// for NATed peers), and a UDP source port is trivially forged, so requiring
	// it would reject honest answers without adding spoofing resistance.
	bool WasRequested(uint32_t ip, uint64_t now) const
	{
		for (auto it = m_retry.lower_bound(Key(ip, MinPort)); it != m_retry.end() && it->first.first == ip;
		     ++it)
		{
			if (it->second.requested &&
			    (now - it->second.lastSent) < AcceptWindowMs)
				return true;
		}
		return false;
	}

	bool TimedOut(uint32_t ip, uint16_t udpPort, uint64_t now)
	{
		const auto it = m_retry.find(Key(ip, udpPort));
		if (it == m_retry.end() || !it->second.pending || now - it->second.lastSent < RequestTimeoutMs)
			return false;
		State& state = it->second;
		state.pending = false;
		if (state.failures < 5u)
			++state.failures;
		state.retryAt = now + Delay(state.failures);
		state.lastTouched = now;
		return true;
	}

	// No transaction ID exists on the wire. Prefer the requested endpoint;
	// an alternate source port is safe only if one unconsumed request fits.
	// Keep a replay marker so a duplicate cannot consume a neighbouring port.
	bool MatchResponse(uint32_t ip, uint16_t sourcePort, uint64_t now, uint16_t& requestedPort) const
	{
		const State* match = nullptr;
		size_t candidates = 0;
		bool cancelled = false;
		for (auto it = m_retry.lower_bound(Key(ip, MinPort)); it != m_retry.end() && it->first.first == ip; ++it)
		{
			const State& state = it->second;
			if (now - state.lastSent >= AcceptWindowMs)
				continue;
			if (state.answered && (state.replyPort == sourcePort || it->first.second == sourcePort))
				return false;
			if (!state.requested)
			{
				// A cancelled request has no observed response port. Its late
				// reply could otherwise consume an independent IP-only match.
				cancelled = cancelled || !state.answered;
				continue;
			}
			++candidates;
			if (match == nullptr || it->first.second == sourcePort)
			{
				match = &state;
				requestedPort = it->first.second;
			}
		}
		return match != nullptr && (requestedPort == sourcePort || (candidates == 1 && !cancelled));
	}

	void Accepted(uint32_t ip, uint16_t requestedPort, uint16_t sourcePort, uint64_t now)
	{
		const auto it = m_retry.find(Key(ip, requestedPort));
		if (it == m_retry.end())
			return;
		State& state = it->second;
		state.pending = state.requested = false;
		state.answered = true;
		state.replyPort = sourcePort;
		state.failures = 0;
		// Do not overwrite replay protection by immediately retrying this endpoint.
		state.retryAt = state.lastSent + AcceptWindowMs;
		state.lastTouched = now;
	}

	void Cancelled(uint32_t ip, uint16_t udpPort)
	{
		const auto it = m_retry.find(Key(ip, udpPort));
		if (it == m_retry.end())
			return;
		// Cancellation withdraws correlation without manufacturing a failure.
		it->second.pending = it->second.requested = false;
		it->second.retryAt = 0;
	}

	void Prune(uint64_t now)
	{
		// Failure history outlives the cooldown it set: dropping it the moment
		// the capped delay expires would restart an unresponsive peer at the
		// shortest delay. It is released after a further idle cap instead.
		for (auto it = m_retry.begin(); it != m_retry.end();)
		{
			if (!it->second.pending && now - it->second.lastTouched >= BackoffCapMs &&
			    now - it->second.lastSent >= AcceptWindowMs && now >= it->second.retryAt + BackoffCapMs)
				it = m_retry.erase(it);
			else
				++it;
		}
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

	static bool Elapsed(uint64_t now, uint64_t deadline)
	{
		return now >= deadline;
	}

	size_t Tracked() const { return m_retry.size(); }

private:
	using Key = std::pair<uint32_t, uint16_t>;
	// Bounds of the per-IP key range; m_retry is ordered by (ip, port).
	static constexpr uint16_t MinPort = 0;
	struct State
	{
		uint64_t retryAt = 0;
		uint64_t lastTouched = 0;
		uint64_t lastSent = 0;
		uint32_t failures = 0;
		bool pending = false;
		bool requested = false;
		bool answered = false;
		uint16_t replyPort = 0;
	};
	size_t m_cursor = 0;
	std::map<Key, State> m_retry;
};
