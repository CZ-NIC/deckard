set -o errexit -o nounset

HEAD="$(git log -1 --format="%H" HEAD)"
MERGEBASE="$(git merge-base origin/master "${HEAD}")"
LOGDIR="$(pwd)"
PYTHON=${PYTHON:-"python3"}
CIDIR="$(dirname "${0}")"

# workaround for Gitlab's missing support for absolute paths in artifacts:
# https://gitlab.com/gitlab-org/gitlab-ci-multi-runner/issues/1011
declare -a LOGS
LOGS[0]=""  # avoid unbound variable error if user does not specify own logs
function collect_logs {
	set +o errexit
	test -n "${LOGS[*]}" && cp "--target-directory=${LOGDIR}" ${LOGS[*]}
}
trap collect_logs EXIT
