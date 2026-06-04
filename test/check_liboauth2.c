/***************************************************************************
 *
 * Copyright (C) 2018-2025 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include "check_liboauth2.h"

#include <stdlib.h>

/*
 * Each suite that needs to drive the HTTP client spins up its own loopback
 * server per test (see test/http_server.h), so there is no shared, suite-wide
 * HTTP server to set up here anymore.
 */

int main(void)
{
	int n_failed;

	SRunner *sr = srunner_create(suite_create("liboauth2"));

	// srunner_set_fork_status(sr, CK_NOFORK);

	srunner_add_suite(sr, oauth2_check_version_suite());
	srunner_add_suite(sr, oauth2_check_mem_suite());
	srunner_add_suite(sr, oauth2_check_log_suite());
	srunner_add_suite(sr, oauth2_check_cfg_suite());
	srunner_add_suite(sr, oauth2_check_util_suite());
	srunner_add_suite(sr, oauth2_check_ipc_suite());
	srunner_add_suite(sr, oauth2_check_cache_suite());
	srunner_add_suite(sr, oauth2_check_jose_suite());
	srunner_add_suite(sr, oauth2_check_http_suite());
	srunner_add_suite(sr, oauth2_check_proto_suite());
	srunner_add_suite(sr, oauth2_check_oauth2_suite());
	srunner_add_suite(sr, oauth2_check_openidc_suite());
#ifdef HAVE_LIBJQ
	srunner_add_suite(sr, oauth2_check_jq_suite());
#endif
#ifdef HAVE_APACHE
	srunner_add_suite(sr, oauth2_check_apache_suite());
#endif
#ifdef HAVE_NGINX
	srunner_add_suite(sr, oauth2_check_nginx_suite());
#endif

	srunner_run_all(sr, CK_VERBOSE);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	oauth2_check_jose_cleanup();
	oauth2_check_http_cleanup();
	oauth2_check_proto_cleanup();
	oauth2_check_oauth2_cleanup();
	oauth2_check_openidc_cleanup();

	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
