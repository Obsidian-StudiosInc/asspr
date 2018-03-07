#!/bin/bash
# runs each command of asspr through valgrind as well as the tests binary
# run from root project directory, or will error

VG="/usr/bin/valgrind --leak-check=yes --leak-check=full --read-var-info=yes"
VG="${VG} --show-reachable=yes --track-origins=yes --error-exitcode=1"

BIN_TEST="$(find .  | grep 'dist/asspr-test')"
BIN="${BIN_TEST%%-*}"

check_rc() {
	[[ ${1} -ne 0 ]] && exit "${1}"
}

test_code() {
	${VG} "${BIN_TEST}" "$@"
	check_rc $?
}

test_bin() {
	${VG} "${BIN}" -a tests/var/lib/assp/ -C tests/etc/assp/ -c -s
}

case "$1" in
	-b | --bin) test_bin ;;
	-c | --code)
		shift
		test_code "$@"
		;;
	*)
		test_code "$@"
		test_bin
		;;
esac

exit 0
