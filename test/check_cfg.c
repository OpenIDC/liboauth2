#include <check.h>

#include "cfg_int.h"
#include <oauth2/mem.h>

static oauth2_log_t *_log = 0;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

typedef struct test_flag_slot_struct {
	char *dummy;
	oauth2_flag_t flag;
} test_flag_slot_struct;

START_TEST(test_flag_slot)
{
	const char *rv = NULL;
	test_flag_slot_struct st = {NULL, OAUTH2_CFG_FLAG_UNSET};

	rv = oauth2_cfg_set_flag_slot(
	    NULL, offsetof(test_flag_slot_struct, flag), NULL);
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), NULL);
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "true");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "false");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "True");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "False");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "TRUE");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "FALSE");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "0");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "1");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "2");
	ck_assert_ptr_ne(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "On");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "Off");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "ON");
	ck_assert_ptr_eq(rv, NULL);

	rv = oauth2_cfg_set_flag_slot(
	    &st, offsetof(test_flag_slot_struct, flag), "OFF");
	ck_assert_ptr_eq(rv, NULL);
}
END_TEST

Suite *oauth2_check_cfg_suite()
{
	Suite *s = suite_create("cfg");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_flag_slot);

	suite_add_tcase(s, c);

	return s;
}
