#!/bin/bash
# runs each command of asspr through valgrind as well as the tests binary
# run from root project directory, or will error

VG="/usr/bin/valgrind --leak-check=yes --leak-check=full --read-var-info=yes"
VG="${VG} --show-reachable=yes --track-origins=yes --error-exitcode=1"

BIN_TEST="$(find .  | grep 'dist/asspr-test')"
BIN="${BIN_TEST%%-*}"

ASSP="build/var/lib/assp/"
CONFIG="build/etc/assp/"

check_rc() {
	[[ ${1} -ne 0 ]] && exit "${1}"
}

init_files() {
	local email emails ext exts

	emails=( abuse admin mailer-daemon postmaster root webmaster )
	exts=( com net org )
	if [[ ! -d "${ASSP}" ]] && [[ ! -d "${CONFIG}" ]]; then
		mkdir -p "${ASSP}"/{discarded,notspam,spam} "${CONFIG}"

		for ext in "${exts[@]}"; do
			echo "domain.${ext}" >> "${CONFIG}/localdomains.txt"
			for email in "${emails[@]}"; do
				echo "${email}@domain.${ext}" \
					>> "${CONFIG}/localaddresses.txt"
			done
		done
	fi
}

test_code() {
	${VG} "${BIN_TEST}" "$@"
	check_rc $?
}

test_bin() {
	init_files

	${VG} "${BIN}" -a "${ASSP}" -C "${CONFIG}" -c -s
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
