//
// test_main.cpp
//
// Test runner for Envy unit tests
// Structured output for CI integration
//
// This file is part of Envy (getenvy.com) (C) 2016-2026
// License: GNU Affero General Public License v3.0 (AGPLv3)
//

#include "test_framework.h"

// Test modules register their tests via these functions
void register_hashlib_tests(TestSuite& suite);
void register_protocol_parser_smoke_tests(TestSuite& suite);
void register_secureident_policy_smoke_tests(TestSuite& suite);
void register_ed2k_hello_capabilities_smoke_tests(TestSuite& suite);
void register_ed2k_hello_golden_tests(TestSuite& suite);
void register_ed2k_kad_settings_smoke_tests(TestSuite& suite);
void register_webhook_registration_smoke_tests(TestSuite& suite);
void register_skin_engine_p0_smoke_tests(TestSuite& suite);
void register_network_interface_selector_smoke_tests(TestSuite& suite);
void register_remote_base64_smoke_tests(TestSuite& suite);
void register_secure_random_smoke_tests(TestSuite& suite);
void register_dc_packet_length_smoke_tests(TestSuite& suite);
void register_ed2k_lock_order_smoke_tests(TestSuite& suite);
void register_envy_thread_policy_smoke_tests(TestSuite& suite);
void register_remote_password_policy_smoke_tests(TestSuite& suite);

int main() {
	TestSuite suite;

	register_hashlib_tests(suite);
	register_protocol_parser_smoke_tests(suite);
	register_secureident_policy_smoke_tests(suite);
	register_ed2k_hello_capabilities_smoke_tests(suite);
	register_ed2k_hello_golden_tests(suite);
	register_ed2k_kad_settings_smoke_tests(suite);
	register_webhook_registration_smoke_tests(suite);
	register_skin_engine_p0_smoke_tests(suite);
	register_network_interface_selector_smoke_tests(suite);
	register_remote_base64_smoke_tests(suite);
	register_secure_random_smoke_tests(suite);
	register_dc_packet_length_smoke_tests(suite);
	register_ed2k_lock_order_smoke_tests(suite);
	register_envy_thread_policy_smoke_tests(suite);
	register_remote_password_policy_smoke_tests(suite);

	int failures = suite.run_all_tests();

	return (failures == 0) ? 0 : 1;
}
