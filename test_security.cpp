#include "Envy/StdAfx.h"
#include "Envy/RemoteSecurity.h"
#include "Envy/Settings.h"
#include <iostream>
#include <string>

// Simple test for security functions
int main() {
    std::cout << "Testing Envy Remote Security Features..." << std::endl;

    // Test 1: IP Access Control
    IN_ADDR testIP;
    inet_pton(AF_INET, "127.0.0.1", &testIP);
    bool localhostAllowed = CRemoteSecurity::IsRemoteAccessAllowed(testIP);
    std::cout << "Localhost access allowed: " << (localhostAllowed ? "YES" : "NO") << std::endl;

    inet_pton(AF_INET, "192.168.1.100", &testIP);
    bool lanAllowed = CRemoteSecurity::IsRemoteAccessAllowed(testIP);
    std::cout << "LAN IP access allowed: " << (lanAllowed ? "YES" : "NO") << std::endl;

    inet_pton(AF_INET, "8.8.8.8", &testIP);
    bool wanAllowed = CRemoteSecurity::IsRemoteAccessAllowed(testIP);
    std::cout << "WAN IP access allowed: " << (wanAllowed ? "YES" : "NO") << std::endl;

    // Test 2: CIDR Parsing
    inet_pton(AF_INET, "192.168.1.50", &testIP);
    bool inCIDR = CRemoteSecurity::IsIPInCIDR(testIP, L"192.168.1.0/24");
    std::cout << "192.168.1.50 in 192.168.1.0/24: " << (inCIDR ? "YES" : "NO") << std::endl;

    // Test 3: Password Hashing
    std::string hash;
    bool hashResult = CRemoteSecurity::HashPassword("testpassword", hash);
    std::cout << "Password hashing works: " << (hashResult ? "YES" : "NO") << std::endl;
    if (hashResult) {
        bool verifyResult = CRemoteSecurity::VerifyPassword("testpassword", hash);
        std::cout << "Password verification works: " << (verifyResult ? "YES" : "NO") << std::endl;
    }

    // Test 4: CSRF Token Generation
    RemoteSession session;
    IN_ADDR sessionIP;
    inet_pton(AF_INET, "127.0.0.1", &sessionIP);
    bool sessionCreated = CRemoteSecurity::CreateSession(sessionIP, session);
    std::cout << "Session creation works: " << (sessionCreated ? "YES" : "NO") << std::endl;
    if (sessionCreated) {
        bool tokenValid = CRemoteSecurity::ValidateCSRFToken(session.sessionId, session.csrfToken);
        std::cout << "CSRF token validation works: " << (tokenValid ? "YES" : "NO") << std::endl;
    }

    std::cout << "Security tests completed!" << std::endl;
    return 0;
}
