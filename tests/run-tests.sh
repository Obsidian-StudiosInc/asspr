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
	local dir email emails ext exts i z

	emails=( abuse admin mailer-daemon postmaster root webmaster )
	exts=( com net org )
	i=0
	if [[ ! -d "${ASSP}" ]] && [[ ! -d "${CONFIG}" ]]; then
		mkdir -p "${ASSP}"/{discarded,notspam,spam,viruses} "${CONFIG}"

		for ext in "${exts[@]}"; do
			echo "domain.${ext}" >> "${CONFIG}/localdomains.txt"
			for email in "${emails[@]}"; do
				echo "${email}@domain.${ext}" \
					>> "${CONFIG}/localaddresses.txt"
				for dir in discarded notspam spam viruses; do
					# shellcheck disable=SC2034
					for z in 1 2; do
						(( i+=1 ))
						echo \
"From: <${dir}mer@${dir}.com>
Date: $(date)
To: ${email}@domain.${ext}
Subject: ${dir^} email subject
" > "${ASSP}${dir}/${i}.eml"
					done
				done
			done
		done

	fi
}

test_code() {
	${VG} "${BIN_TEST}" "$@"
	check_rc $?
}

test_bin() {
	local arg ARGS

	init_files

	${VG} "${BIN}" -a "${ASSP}" -C "${CONFIG}" -c -s -e "admin@domain.com"
	check_rc $?

	${VG} "${BIN}" -a "${ASSP}" -C "${CONFIG}" -c -s -d "domain.com"
	check_rc $?

	${VG} "${BIN}" -a "${ASSP}" -C "${CONFIG}" -c -s -n -v
	check_rc $?

        ARGS=( E H M S "?" V )
	# skip check_rc all exit with error code by design
        for arg in "${ARGS[@]}"; do
                ${VG} "${BIN}" -a "${ASSP}" -C "${CONFIG}" -"${arg}"
        done
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
