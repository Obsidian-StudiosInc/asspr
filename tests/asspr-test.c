/***************************************************************************
 *  Copyright 2018 Obsidian-Studios, Inc.
 *  Author "William L. Thomson Jr." <wlt@o-sinc.com>
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <check.h>

#include "../src/asspr.h"

START_TEST (test_asspr)
{
    initRptPtr();
    ck_assert(rpts_ptr);
    free(rpts_ptr);
    ck_assert(rpts_ptr);
}
END_TEST

Suite * asspr_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("asspr");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_asspr);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = asspr_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
