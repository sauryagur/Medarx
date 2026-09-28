#!/usr/bin/env bash
#
# The Medarx Phase 1 environment preflight. **This script is the test for the
# infrastructure task**: there is no pytest for `infra/`, because what it checks
# is not a function's behaviour but whether this host can run the thing at all.
#
#   bash infra/verify_env.sh
#
# Run it from anywhere; paths are resolved relative to this file.
#
# ## What it checks, and in what order
#
#   1. `docker version` is reachable — client *and* daemon, because a client
#      with no daemon passes the version check and then fails every container
#      step with a different message.
#   2. The `medarx` network is resolvable, so a `br-` interface id can be
#      derived. Component I's capture needs that id and it must never be written
#      down: an interface name is 15 characters including the `br-` prefix,
#      because Linux truncates to IFNAMSIZ - 1.
#   3. Free disk on the repository's filesystem, printed. Not asserted: disk
#      pressure does not make the kernel refuse, it makes image pulls fail in
#      ways that look like corrupt layers.
#   4. The memory budget the plan remembered, printed against what is measured
#      now. The remembered figure is a claim about a machine measured on another
#      day; the whole point of printing both is that the difference is visible.
#   5. The virtual environment is not under `/tmp`. Asserted, and fatally: `/tmp`
#      is a tmpfs, so a venv there consumes RAM rather than disk, and a
#      development machine with 3 GiB available does not have 3 GiB to give.
#   6. `docker compose -f infra/compose.yaml config` is valid. Asserted, and
#      fatally: every subsequent step is an invocation of what this parses.
#
# ## The three booleans
#
# The three headline results are `docker_usable`, `network_resolvable` and
# `compose_valid`. Checks 3 and 4 are printed facts and check 5 is a hard stop;
# a check that is printed but not enforced is a comment, and this project has
# been bitten by those.
#
# Exit status is 0 only when all three booleans are true.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/infra/compose.yaml"
NETWORK="medarx"

#: The budget the plan remembered for the development machine, in GiB. Printed
#: next to the measured figures and never asserted against: it is a record of
#: one machine on one day, and a preflight that failed because a host had grown
#: would be a preflight that gets disabled.
REMEMBERED_TOTAL_GIB=15.3
REMEMBERED_AVAILABLE_GIB=4.8
REMEMBERED_SWAP="zero"
REMEMBERED_CORES=12

say() { printf '%s\n' "$*"; }
rule() { printf -- '---------------------------------------------------------------\n'; }

fail_hard() { printf 'verify_env: %s\n' "$*" >&2; exit 1; }

docker_usable=false
network_resolvable=false
compose_valid=false
network_created_here=false

rule
say "Medarx Phase 1 — environment preflight"
rule

# -- 1. Docker, client and daemon --------------------------------------------

say ""
say "[1/6] docker"
if ! command -v docker >/dev/null 2>&1; then
    say "      FAIL  no docker on PATH"
else
    client_version="$(docker version --format '{{.Client.Version}}' 2>/dev/null || true)"
    daemon_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    if [ -z "$daemon_version" ]; then
        say "      FAIL  the docker daemon is not answering; a client alone will"
        say "            pass a version check and then fail every container step"
    else
        docker_usable=true
        say "      OK    client $client_version, daemon $daemon_version"
    fi
    compose_version="$(docker compose version --short 2>/dev/null || true)"
    if [ -n "$compose_version" ]; then
        say "      OK    compose $compose_version"
    else
        say "      FAIL  the compose plugin is not installed; infra/compose.yaml"
        say "            cannot be validated or started without it"
        docker_usable=false
    fi
fi

# -- 2. The medarx network, and the bridge id derived from it ----------------

say ""
say "[2/6] the '$NETWORK' network"
if [ "$docker_usable" = true ]; then
    if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
        # Created here so the check is about resolvability and interface
        # derivation rather than about whether the stack happens to be up. The
        # script says which it did, because a network this run made is not
        # evidence that compose can make one.
        if docker network create "$NETWORK" >/dev/null 2>&1; then
            network_created_here=true
        fi
    fi
    if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
        say "      FAIL  network '$NETWORK' does not exist and could not be created."
        say "            Bring the stack up first:  docker compose -f infra/compose.yaml up -d"
    else
        network_resolvable=true
        say "      OK    network '$NETWORK' resolves$(
            [ "$network_created_here" = true ] && printf ' (created by this run)')"
    fi
else
    say "      SKIP  docker is not usable"
fi

bridge_id=""
if [ "$network_resolvable" = true ]; then
    # 12 hex characters, because the interface is "br-" plus 12 and Linux
    # truncates interface names to IFNAMSIZ - 1 = 15.
    network_id="$(docker network inspect -f '{{.Id}}' "$NETWORK")"
    bridge_id="br-$(printf '%s' "$network_id" | cut -c1-12)"
    say "      bridge interface  $bridge_id  (${#bridge_id} characters)"
    if [ "${#bridge_id}" -ne 15 ]; then
        say "      FAIL  a Linux interface name is at most 15 characters;"
        say "            this one cannot be passed to tcpdump -i"
        network_resolvable=false
    fi
    say "      discover it again, any time, with:"
    say "        bash infra/capture/start_capture.sh interface $NETWORK"
fi

# -- 3. Free disk -------------------------------------------------------------

say ""
say "[3/6] free disk on the repository's filesystem"
df -h "$REPO_ROOT" | tail -n 1 | while read -r fs size used avail pct rest; do
    say "      filesystem $fs  $size total, $used used, $avail available ($pct)"
done
say "      this is printed, not asserted: disk pressure does not refuse, it makes"
say "      image pulls fail in ways that look like corrupt layers. If this number"
say "      is low, 'docker image prune -a' on this host recovered 10.01 GB once."

# -- 4. Memory against the remembered budget ---------------------------------

say ""
say "[4/6] memory"
if [ -r /proc/meminfo ]; then
    mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    mem_available_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    swap_total_kb="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
    to_gib() { awk -v k="$1" 'BEGIN {printf "%.1f", k / 1048576}'; }
    cores="$(nproc 2>/dev/null || echo '?')"
    measured_total="$(to_gib "$mem_total_kb")"
    measured_available="$(to_gib "$mem_available_kb")"
    if [ "$swap_total_kb" -eq 0 ]; then
        measured_swap="zero"
    else
        measured_swap="$(to_gib "$swap_total_kb") GiB"
    fi
    say "      remembered  ${REMEMBERED_TOTAL_GIB} GiB total / ~${REMEMBERED_AVAILABLE_GIB} GiB available / ${REMEMBERED_SWAP} swap / ${REMEMBERED_CORES} cores"
    say "      measured    ${measured_total} GiB total / ${measured_available} GiB available / ${measured_swap} swap / ${cores} cores"
    say "      the remembered figure is a record of another machine on another day."
    say "      It is printed so the difference is visible, and not asserted, so a"
    say "      preflight does not get disabled for having been right once."
    # 1 GiB is 1048576 kB. `/proc/meminfo` reports kibibytes.
    if [ "$mem_available_kb" -lt 1048576 ]; then
        say "      WARN  under 1 GiB available. Both demo beats start a container,"
        say "            load a spaCy model and run a capture; this is workable but"
        say "            tight, and a swap file is the usual answer on a host that"
        say "            has none."
    fi
else
    say "      SKIP  /proc/meminfo is not readable here, so nothing is measured"
    say "            and nothing about memory is claimed"
fi

# -- 5. The virtual environment is not on tmpfs ------------------------------

say ""
say "[5/6] the virtual environment"
venv="$REPO_ROOT/backend/.venv"
venv_real="$(readlink -f "$venv" 2>/dev/null || printf '%s' "$venv")"
say "      venv        $venv_real"
case "$venv_real" in
    /tmp/*|/var/tmp/*)
        fail_hard "the venv resolves under a tmpfs ($venv_real). /tmp is RAM here, so"
        ;;
    *)
        say "      OK    not under /tmp"
        ;;
esac

# -- 6. The compose file parses ----------------------------------------------

say ""
say "[6/6] docker compose -f infra/compose.yaml config"
if [ ! -f "$COMPOSE_FILE" ]; then
    say "      FAIL  $COMPOSE_FILE does not exist"
else
    if compose_output="$(docker compose -f "$COMPOSE_FILE" config 2>&1)"; then
        compose_valid=true
        say "      OK    the file parses and resolves"
        # `config --services` lists only the services the *active* profiles
        # select, so with no profile enabled `orthanc` and `capture` are absent
        # from it entirely. Enumerating with every profile on is what makes the
        # partition below a fact about the file rather than about this shell.
        all_services="$(docker compose --profile orthanc --profile capture \
            -f "$COMPOSE_FILE" config --services 2>/dev/null | sort)"
        say "      services a default 'up -d' starts:"
        printf '%s\n' "$all_services" | grep -v -E '^(orthanc|capture)$' \
            | sed 's/^/        /'
        profiled="$(printf '%s\n' "$all_services" | grep -E '^(orthanc|capture)$' || true)"
        say "      services behind a profile, which stay down unless asked for:"
        if [ -n "$profiled" ]; then
            printf '%s\n' "$profiled" | sed 's/^/        /'
        else
            say "        (none — so a default bring-up starts every service above)"
        fi
    else
        say "      FAIL  docker compose rejected the file:"
        printf '%s\n' "$compose_output" | sed 's/^/        /'
    fi
fi

# -- The three booleans -------------------------------------------------------

rule
say "docker_usable      = $docker_usable"
say "network_resolvable = $network_resolvable"
say "compose_valid      = $compose_valid"
rule

if [ "$docker_usable" = true ] && [ "$network_resolvable" = true ] \
   && [ "$compose_valid" = true ]; then
    say "preflight PASSED"
    if [ "$network_created_here" = true ]; then
        say ""
        say "note: the '$NETWORK' network did not exist and was created by this run."
        say "      That is enough to derive $bridge_id, and not enough to show that"
        say "      'docker compose up -d' can create one. Run it to find out."
    fi
    exit 0
fi

say "preflight FAILED" >&2
exit 1
