#include <check.h>

#include "oauth2/cfg.h"
#include <oauth2/mem.h>

#include "cfg_int.h"

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

typedef struct test_cfg_slot_struct {
	oauth2_flag_t flag;
	oauth2_uint_t uint;
} test_cfg_slot_struct;

START_TEST(test_flag_slot)
{
	const char *rv = NULL;
	test_cfg_slot_struct st = {OAUTH2_CFG_FLAG_UNSET,
				   OAUTH2_CFG_UINT_UNSET};

	rv = oauth2_cfg_set_flag_slot(
	    NULL, offsetof(test_cfg_slot_struct, flag), NULL);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.flag, OAUTH2_CFG_FLAG_UNSET);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      NULL);
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, OAUTH2_CFG_FLAG_UNSET);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.flag, OAUTH2_CFG_FLAG_UNSET);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "true");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "false");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "True");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "False");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "TRUE");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "FALSE");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "0");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "1");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "2");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.flag, OAUTH2_CFG_FLAG_UNSET);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "On");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "Off");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "ON");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, true);

	rv = oauth2_cfg_set_flag_slot(&st, offsetof(test_cfg_slot_struct, flag),
				      "OFF");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.flag, false);
}
END_TEST

START_TEST(test_uint_slot)
{
	const char *rv = NULL;
	test_cfg_slot_struct st = {OAUTH2_CFG_FLAG_UNSET,
				   OAUTH2_CFG_UINT_UNSET};

	rv = oauth2_cfg_set_uint_slot(
	    NULL, offsetof(test_cfg_slot_struct, uint), NULL);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.uint, OAUTH2_CFG_UINT_UNSET);

	rv = oauth2_cfg_set_uint_slot(&st, offsetof(test_cfg_slot_struct, uint),
				      NULL);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.uint, OAUTH2_CFG_UINT_UNSET);

	rv = oauth2_cfg_set_uint_slot(&st, offsetof(test_cfg_slot_struct, uint),
				      "");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.uint, OAUTH2_CFG_UINT_UNSET);

	rv = oauth2_cfg_set_uint_slot(&st, offsetof(test_cfg_slot_struct, uint),
				      "1two");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.uint, OAUTH2_CFG_UINT_UNSET);

	rv = oauth2_cfg_set_uint_slot(&st, offsetof(test_cfg_slot_struct, uint),
				      "-1");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_uint_eq(st.uint, OAUTH2_CFG_UINT_UNSET);

	rv = oauth2_cfg_set_uint_slot(&st, offsetof(test_cfg_slot_struct, uint),
				      "1");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.uint, 1);
}
END_TEST

START_TEST(test_target_pass)
{

	oauth2_cfg_target_pass_t *cfg = NULL, *cfg2 = NULL, *cfg3 = NULL;
	char *rv = NULL;

	cfg = oauth2_cfg_target_pass_init(_log);
	ck_assert_ptr_ne(cfg, NULL);

	rv = oauth2_cfg_set_target_pass_options(_log, NULL, NULL);
	ck_assert_ptr_ne(rv, NULL);
	oauth2_mem_free(rv);

	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_envvars(cfg), true);
	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_headers(cfg), true);
	ck_assert_ptr_eq(oauth2_cfg_target_pass_get_authn_header(cfg), NULL);
	ck_assert_str_eq(oauth2_cfg_target_pass_get_prefix(cfg),
			 "OAUTH2_CLAIM_");
	ck_assert_str_eq(oauth2_cfg_target_get_remote_user_claim(cfg), "sub");

	rv = oauth2_cfg_set_target_pass_options(
	    _log, cfg,
	    "envvars=false&headers=false&authn_header=auth&prefix=oidc&remote_"
	    "user_claim=preferred_username");
	ck_assert_ptr_eq(rv, NULL);

	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_envvars(cfg), false);
	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_headers(cfg), false);
	ck_assert_str_eq(oauth2_cfg_target_pass_get_authn_header(cfg), "auth");
	ck_assert_str_eq(oauth2_cfg_target_pass_get_prefix(cfg), "oidc");
	ck_assert_str_eq(oauth2_cfg_target_get_remote_user_claim(cfg),
			 "preferred_username");

	oauth2_cfg_target_pass_merge(_log, NULL, NULL, NULL);

	cfg2 = oauth2_cfg_target_pass_init(_log);
	ck_assert_ptr_ne(cfg2, NULL);
	cfg3 = oauth2_cfg_target_pass_init(_log);
	ck_assert_ptr_ne(cfg3, NULL);
	oauth2_cfg_target_pass_merge(_log, cfg2, cfg, cfg3);

	oauth2_cfg_target_pass_free(_log, cfg3);
	oauth2_cfg_target_pass_free(_log, cfg2);
	oauth2_cfg_target_pass_free(_log, cfg);
}
END_TEST

Suite *oauth2_check_cfg_suite()
{
	Suite *s = suite_create("cfg");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_flag_slot);
	tcase_add_test(c, test_uint_slot);
	tcase_add_test(c, test_target_pass);

	suite_add_tcase(s, c);

	return s;
}
