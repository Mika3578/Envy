# Envy Development Roadmap

**Last Updated:** January 16, 2026 (Updated for Kad2 completion and compatibility verification)
**Based on:** Current codebase inspection (`docs/STATUS.md`)
**Approach:** Phased, evidence-based development priorities

This roadmap prioritizes fixes based on actual code analysis, focusing on stability and user experience first, then protocol completeness.

## 📊 Current State Summary

- **Build System:** ✅ VS 2022 functional, CMake partial
- **UI Framework:** ✅ MFC/Unicode complete
- **Protocols:** ✅ G2 full, ⚠️ BT partial (v2 foundation), ✅ ED2K enhanced, ✅ Kad complete
- **Performance:** ⚠️ UI blocking risks identified
- **Testing:** ⚠️ Framework ready, integration tests added
- **Code Quality:** ⚠️ Few remaining TODO/FIXME markers, improved error handling

---

## 🚀 Phase 0: Build & Infrastructure Sanity (✅ COMPLETE)

**Status:** Complete - Foundation established
**Duration:** Completed in prior development
**Evidence:** Working VS builds, CI/CD active

### Completed Tasks
- ✅ Visual Studio 2022 (v145) migration
- ✅ GitHub Actions CI/CD pipeline
- ✅ Basic CMake for HashLib
- ✅ Code formatting (.clang-format)
- ✅ Static analysis tools
- ✅ Google Test framework integration

**Impact:** Development environment stable, automated quality checks active.

---

## 🚀 Phase 1: Performance & Stability (🔴 CRITICAL - START HERE)

**Status:** Not Started
**Duration:** 2-4 weeks
**Priority:** Highest - Affects all users immediately
**Evidence:** `Envy/WndSearchMonitor.cpp`, `Envy/CtrlDownloads.cpp`, `Envy/NeighboursWithRouting.cpp`

### Problem Statement
Current implementation has multiple UI freeze risks:
- Network operations blocking UI thread
- Synchronous I/O without async patterns
- Large list processing without batching
- Frequent UI updates causing redraw storms

### Critical Tasks

#### 1.1 UI Thread Blocking Fixes
- **Fix Network Operations on UI Thread**
  - Evidence: `Envy/Network.cpp` line 1417 (commented sync ping)
  - Impact: UI freezes during network operations
  - Solution: Move to background threads with message posting

- **Async File I/O Operations**
  - Evidence: Direct `CreateFile/ReadFile` calls in UI context
  - Impact: UI blocks during file operations
  - Solution: Background file processing

#### 1.2 UI Update Batching
- **Download Progress Updates**
  - Evidence: `Envy/CtrlDownloads.cpp` - frequent `Invalidate()` calls
  - Impact: UI redraw storms during downloads
  - Solution: Timer-based batched updates (100-500ms intervals)

- **Search Result Processing**
  - Evidence: `Envy/WndSearchMonitor.cpp` - real-time filtering of large lists
  - Impact: UI freezing during search result processing
  - Solution: Background processing with progress indicators

#### 1.3 List Processing Optimization
- **Position-Based Iteration**
  - Evidence: `Envy/NeighboursWithRouting.cpp` line 108 - manual position iteration
  - Impact: O(n²) complexity for large neighbour lists
  - Solution: Switch to range-based for loops or cached indices

#### 1.4 Memory Management
- **Buffer Reuse**
  - Evidence: Large allocations in hot paths
  - Impact: Memory fragmentation, GC pressure
  - Solution: Object pooling for frequent allocations

### Success Criteria
- ✅ No UI freezing during network operations
- ✅ Smooth scrolling in large lists (1000+ items)
- ✅ Download progress updates don't impact responsiveness
- ✅ Memory usage stable during long sessions

### Testing Approach
- Manual UI responsiveness testing
- Memory profiling with VS Diagnostic Tools
- Network simulation under load

---

## 🚀 Phase 2: ED2K/eMule Protocol Parity (🟡 HIGH PRIORITY)

**Status:** Not Started
**Duration:** 4-6 weeks
**Priority:** High - Core functionality for ED2K network
**Evidence:** `Envy/EDClient.cpp` lines 84-100 (all advanced features disabled)

### Problem Statement
ED2K implementation missing critical modern features:
- No CryptLayer (traffic obfuscation)
- No SecureID (authentication)
- No AICH (file verification)
- No multipacket extensions

### Current vs Target State

| Feature | Current | Target | Priority |
|---------|---------|--------|----------|
| CryptLayer | ❌ Disabled | ✅ Full support | High |
| SecureID | ❌ Disabled | ✅ Authentication | High |
| AICH | ❌ Stub | ✅ Hash verification | High |
| Multi-packet | ❌ Disabled | ✅ Extensions | Medium |
| SourceEx2 | ❌ Disabled | ✅ Exchange | Medium |
| Unicode | ❌ Basic | ✅ Full UTF-8 | Low |

### Implementation Tasks

#### 2.1 CryptLayer Obfuscation
- **Protocol Analysis**
  - Study eMule CryptLayer specification
  - Implement RC4-based obfuscation
- **Integration Points**
  - `Envy/EDClient.cpp` - enable flag, add handshake
  - `Envy/Connection.cpp` - encrypt/decrypt data streams
- **Testing**
  - Interop with eMule clients
  - Fallback to non-obfuscated connections

#### 2.2 SecureID Authentication
- **Client Identification**
  - Implement SecureID generation/validation
  - Server authentication handshake
- **Integration**
  - `Envy/EDClient.cpp` - add to connection setup
  - Server list integration

#### 2.3 AICH Hash Verification
- **Merkle Tree Implementation**
  - Complete AICH hash tree construction
  - Verification during downloads
- **Integration**
  - `Envy/FileIdentifier.h` - add AICH support
  - Download verification pipeline

#### 2.4 Multi-packet Extensions
- **Protocol Extension**
  - Implement multi-packet framing
  - Backward compatibility
- **Performance Benefits**
  - Reduced packet overhead
  - Better large file handling

### Success Criteria
- ✅ Interoperability with modern eMule clients
- ✅ Secure connections (CryptLayer)
- ✅ File verification (AICH) working
- ✅ No regressions in basic ED2K functionality

### Risk Assessment
- **High Risk:** CryptLayer implementation complexity
- **Medium Risk:** AICH integration with existing hash system
- **Low Risk:** Multi-packet extensions (additive feature)

---

## 🚀 Phase 3: Kademlia DHT Parity (✅ COMPLETE - January 2026)

**Status:** Complete - Wire-Compatible with eMule/aMule
**Duration:** Completed January 2026
**Priority:** High - Essential for ED2K network scaling
**Evidence:** 
- `Envy/Kademlia.cpp` (full Kad2 implementation)
- `Envy/Kademlia.h` (Kad2RoutingTable, KadContact structures)
- `Envy/HostCache.cpp` (nodes.dat import with full version support)
- `docs/KAD2_COMPATIBILITY_REPORT.md` (comprehensive compatibility verification)

### Problem Statement (RESOLVED)
Kademlia Kad2 implementation is now complete and wire-compatible:
- ✅ Full bootstrap and routing operations
- ✅ FIND_NODE search support
- ✅ PING/PONG for node discovery
- ✅ XOR distance calculation (K=10, matching eMule/aMule)
- ✅ nodes.dat import (versions 0-3, bootstrap edition)
- ✅ Request tracking (outstanding request management)
- ✅ IP endianness handling (host-order storage, network-order conversion)

### Current vs Target State

| Operation | Current | Target | Status |
|-----------|---------|--------|--------|
| BOOTSTRAP (Kad2) | ✅ Full | ✅ Full | ✅ Complete |
| HELLO/PING (Kad2) | ✅ Full | ✅ Full | ✅ Complete |
| FIND_NODE (Kad2) | ✅ Full | ✅ Full | ✅ Complete |
| Wire Compatibility | ✅ eMule/aMule | ✅ eMule/aMule | ✅ Verified |
| nodes.dat Import | ✅ v0-3 | ✅ v0-3 | ✅ Complete |
| PUBLISH | ❌ Not Implemented | ✅ Full | 🟡 Future |
| FIREWALL_CHECK | ❌ Not Implemented | ✅ Full | 🟡 Future |

### Implementation Tasks

#### 3.1 Complete Kad Opcodes
- **PUBLISH Operations** (0x30/0x31)
  - Keyword publishing to DHT
  - File hash indexing
  - Integration with ED2K search

- **Firewall Check** (0x50/0x51)
  - NAT detection
  - Firewall traversal support

#### 3.2 XOR Distance Bug Fix
- **Distance Calculation**
  - Verify XOR implementation
  - Test with known Kad networks
- **Routing Table**
  - Node organization fixes
  - Bucket maintenance

#### 3.3 Kad Nodes Import
- **nodes.dat Support**
  - Parse existing Kad network dumps
  - Bootstrap from imported nodes
- **Persistence**
  - Save/restore Kad routing table

#### 3.4 Full DHT Indexing
- **Search Implementation**
  - Recursive node lookups
  - Value storage/retrieval
- **Replication**
  - Data replication across nodes
  - Maintenance operations

### Success Criteria
- ✅ Successful bootstrap into Kad network
- ✅ File searches working via Kad
- ✅ Firewall detection functional
- ✅ Routing table persistence
- ✅ No distance calculation errors

### Compatibility Verification
- ✅ **eMule (srchybrid)** - 100% wire-compatible (verified)
- ✅ **aMule** - 100% wire-compatible (verified)
- ⚠️ **Shareaza/MLDonkey** - No Kad2 implementation found to verify
- **Reference:** `docs/KAD2_COMPATIBILITY_REPORT.md` for detailed verification

### Risk Assessment (RESOLVED)
- ✅ **XOR distance** - Verified correct (K=10, matching eMule/aMule)
- ✅ **Kad opcode implementation** - Complete and wire-compatible
- ✅ **nodes.dat import** - Full version support implemented

---

## 🚀 Phase 4: Testing & Quality Assurance (🟢 MEDIUM PRIORITY)

**Status:** Framework Ready
**Duration:** 4-6 weeks
**Priority:** Medium - Essential for long-term stability
**Evidence:** `tests/CMakeLists.txt` (framework present, no tests), 15 TODO/FIXME markers

### Problem Statement
Zero automated testing despite framework being ready:
- No unit tests for core functionality
- No protocol validation
- No regression testing
- Manual testing only

### Implementation Tasks

#### 4.1 Re-establish Testing Infrastructure
- **Testing Framework**
  - Restore Google Test integration
  - Re-implement test runner scripts
  - Set up CI/CD test execution

#### 4.2 Core Unit Tests
- **HashLib Tests**
  - MD4, MD5, SHA-1, SHA-256 algorithms
  - ED2K hash computation
  - Performance benchmarks

- **Network Protocol Tests**
  - Packet parsing/validation
  - Handshake sequences
  - Error condition handling

#### 4.2 Protocol Integration Tests
- **ED2K Interoperability**
  - Connection handshakes
  - File transfer validation
  - Search/response cycles

- **Kad Network Tests**
  - Bootstrap sequences
  - Search operations
  - Node communication

#### 4.3 Performance & Stress Tests
- **UI Responsiveness**
  - Large list handling
  - Concurrent operations
  - Memory usage monitoring

- **Network Load Testing**
  - High connection counts
  - Large file transfers
  - Network saturation scenarios

#### 4.4 CI/CD Integration
- **Automated Testing**
  - Pre-merge test execution
  - Coverage reporting
  - Performance regression detection

### Success Criteria
- ✅ 60%+ code coverage on core components
- ✅ All protocol handshakes validated
- ✅ Performance benchmarks established
- ✅ CI/CD testing fully integrated

---

## 🚀 Phase 5: Advanced Features (🔵 FUTURE)

**Status:** Not Started
**Duration:** 8-12 weeks
**Priority:** Low - After stability achieved

### IPv6 Support
- Network layer updates
- Dual-stack operation
- Backward compatibility

### BT v2 Support
- ✅ BEP-52 foundation implemented (SHA-256, hybrid support)
- 🔄 Merkle tree verification (metadata parsing pending)
- 🔄 Peer wire extensions (next phase)

### Modern C++ Migration
- C++17 → C++20 transition
- Smart pointer adoption
- Constexpr usage

---

## 📈 Success Metrics

### Phase 1 (Performance)
- UI responsiveness: <100ms response times
- Memory usage: <500MB during normal operation
- No UI freezes during network operations

### Phase 2-3 (Protocols)
- ED2K: Full interoperability with eMule 0.70+
- Kad: Successful network bootstrap and searches
- BT: Stable operation with modern clients

### Phase 4 (Quality)
- Testing: Framework restored and functional
- Test coverage: >60% on core components
- CI/CD: All builds passing, automated testing
- Bug rate: <5 new bugs per release

---

## 🎯 Development Principles

### Evidence-Based Planning
- All priorities based on code inspection, not speculation
- User impact drives sequencing (performance first)
- Protocol gaps validated through feature flags and TODOs

### Incremental Approach
- Each phase delivers working functionality
- Backward compatibility maintained
- Testing integrated at each step

### Risk Management
- Critical UI issues addressed before feature work
- Protocol implementations tested against reference clients
- Performance profiling guides optimizations

---

## 📋 Implementation Notes

### Dependencies
- **Phase 1:** No external dependencies (code refactoring)
- **Phase 2:** Protocol specification analysis
- **Phase 3:** Kad network access for testing
- **Phase 4:** Testing framework expansion

### Testing Strategy
- **Manual Testing:** UI responsiveness, basic functionality
- **Unit Tests:** Algorithm correctness, edge cases
- **Integration Tests:** Protocol interoperability
- **Performance Tests:** Benchmarks, memory profiling

### Documentation Updates
- Update `docs/STATUS.md` after each phase completion
- Maintain accurate feature matrices
- Document known limitations clearly

This roadmap reflects the actual current state and focuses on delivering user value through stability and completeness rather than new features.
