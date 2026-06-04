#include <check.h>

#include "check_liboauth2.h"
#include "oauth2/cfg.h"
#include <oauth2/mem.h>
#include <string.h>

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
	oauth2_time_t time;
} test_cfg_slot_struct;

typedef struct test_cfg_str_struct {
	char *str;
} test_cfg_str_struct;

static char *_cfg_dummy_set_cb(oauth2_log_t *log, const char *value,
			       const oauth2_nv_list_t *params, void *cfg)
{
	return NULL;
}

static void _cfg_dummy_ctx_free(oauth2_log_t *log, void *ptr)
{
}

static oauth2_cfg_ctx_funcs_t _cfg_dummy_funcs = {NULL, NULL,
						  _cfg_dummy_ctx_free};

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

	st.flag = OAUTH2_CFG_FLAG_UNSET;
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
	ck_assert_ptr_eq(oauth2_cfg_target_get_json_payload_claim(cfg), NULL);

	rv = oauth2_cfg_set_target_pass_options(
	    _log, cfg,
	    "envvars=false&headers=false&authn_header=auth&prefix=oidc&remote_"
	    "user_claim=preferred_username&json_payload_claim=my_json");
	ck_assert_ptr_eq(rv, NULL);

	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_envvars(cfg), false);
	ck_assert_uint_eq(oauth2_cfg_target_pass_get_as_headers(cfg), false);
	ck_assert_str_eq(oauth2_cfg_target_pass_get_authn_header(cfg), "auth");
	ck_assert_str_eq(oauth2_cfg_target_pass_get_prefix(cfg), "oidc");
	ck_assert_str_eq(oauth2_cfg_target_get_remote_user_claim(cfg),
			 "preferred_username");
	ck_assert_str_eq(oauth2_cfg_target_get_json_payload_claim(cfg),
			 "my_json");

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

START_TEST(test_time_slot)
{
	const char *rv = NULL;
	test_cfg_slot_struct st = {OAUTH2_CFG_FLAG_UNSET, OAUTH2_CFG_UINT_UNSET,
				   OAUTH2_CFG_TIME_UNSET};

	rv = oauth2_cfg_set_time_slot(
	    NULL, offsetof(test_cfg_slot_struct, time), "1");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_time_slot(&st, offsetof(test_cfg_slot_struct, time),
				      NULL);
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_time_slot(&st, offsetof(test_cfg_slot_struct, time),
				      "");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_time_slot(&st, offsetof(test_cfg_slot_struct, time),
				      "1two");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_time_slot(&st, offsetof(test_cfg_slot_struct, time),
				      "-1");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_time_slot(&st, offsetof(test_cfg_slot_struct, time),
				      "3600");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_uint_eq(st.time, 3600);
}
END_TEST

START_TEST(test_str_slot)
{
	const char *rv = NULL;
	test_cfg_str_struct st = {NULL};

	rv = oauth2_cfg_set_str_slot(NULL, offsetof(test_cfg_str_struct, str),
				     "hello");
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_ptr_eq(st.str, NULL);

	rv = oauth2_cfg_set_str_slot(&st, offsetof(test_cfg_str_struct, str),
				     NULL);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_ptr_eq(st.str, NULL);

	rv = oauth2_cfg_set_str_slot(&st, offsetof(test_cfg_str_struct, str),
				     "hello");
	ck_assert_ptr_eq(rv, NULL);
	ck_assert_str_eq(st.str, "hello");

	oauth2_mem_free(st.str);
	st.str = NULL;
}
END_TEST

START_TEST(test_crypto_passphrase)
{
	const char *rv = NULL;
	const char *p = NULL;

	rv = oauth2_crypto_passphrase_set(_log, NULL, "secret1");
	ck_assert_ptr_eq(rv, NULL);

	// a second set frees the previously stored passphrase
	rv = oauth2_crypto_passphrase_set(_log, NULL, "secret2");
	ck_assert_ptr_eq(rv, NULL);

	p = oauth2_crypto_passphrase_get(_log);
	ck_assert_ptr_ne(p, NULL);
	ck_assert_str_eq(p, "secret2");
}
END_TEST

START_TEST(test_cfg_ctx)
{
	oauth2_cfg_ctx_t *ctx = NULL, *clone = NULL, *ctx2 = NULL;

	// free(NULL) is a no-op
	oauth2_cfg_ctx_free(_log, NULL);

	ctx = oauth2_cfg_ctx_init(_log);
	ck_assert_ptr_ne(ctx, NULL);

	// clone(NULL) returns NULL
	clone = oauth2_cfg_ctx_clone(_log, NULL);
	ck_assert_ptr_eq(clone, NULL);

	// clone of a ctx that has no callbacks
	clone = oauth2_cfg_ctx_clone(_log, ctx);
	ck_assert_ptr_ne(clone, NULL);
	oauth2_cfg_ctx_free(_log, clone);

	oauth2_cfg_ctx_free(_log, ctx);

	// free path that invokes callbacks->free() on a non-NULL ptr
	ctx2 = oauth2_cfg_ctx_init(_log);
	ck_assert_ptr_ne(ctx2, NULL);
	ctx2->ptr = (void *)0x1;
	ctx2->callbacks = &_cfg_dummy_funcs;
	oauth2_cfg_ctx_free(_log, ctx2);
}
END_TEST

START_TEST(test_set_options)
{
	char *rv = NULL;
	int dummy_cfg = 0;
	static const oauth2_cfg_set_options_ctx_t set[] = {
	    {"typeA", _cfg_dummy_set_cb},
	    {"typeB", _cfg_dummy_set_cb},
	    {NULL, NULL}};

	// NULL cfg -> no-op, returns NULL
	rv = oauth2_cfg_set_options(_log, NULL, "typeA", "val", NULL, set);
	ck_assert_ptr_eq(rv, NULL);

	// known type -> callback runs, returns NULL (success)
	rv =
	    oauth2_cfg_set_options(_log, &dummy_cfg, "typeA", "val", NULL, set);
	ck_assert_ptr_eq(rv, NULL);

	// unknown type -> error string listing the valid types
	rv = oauth2_cfg_set_options(_log, &dummy_cfg, "nope", "val", NULL, set);
	ck_assert_ptr_ne(rv, NULL);
	ck_assert_ptr_ne(strstr(rv, "typeA"), NULL);
	ck_assert_ptr_ne(strstr(rv, "typeB"), NULL);
	oauth2_mem_free(rv);
}
END_TEST

Suite *oauth2_check_cfg_suite()
{
	Suite *s = suite_create("cfg");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_flag_slot);
	tcase_add_test(c, test_uint_slot);
	tcase_add_test(c, test_time_slot);
	tcase_add_test(c, test_str_slot);
	tcase_add_test(c, test_crypto_passphrase);
	tcase_add_test(c, test_cfg_ctx);
	tcase_add_test(c, test_set_options);
	tcase_add_test(c, test_target_pass);

	suite_add_tcase(s, c);

	return s;
}
