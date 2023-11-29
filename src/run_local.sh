#!/bin/bash

TMUX_SESSION='thetacrypt-local'

N=4

# If session does not exist yet, spawn it

function main {
	if (( $# != 1 )); then
		usage
	fi

	cmd=$1

	setup_multiplexer

	if [ "${cmd}" = "start" ]; then
		start_thetacrypt
	elif [ "${cmd}" = "stop" ]; then
		stop_thetacrypt
	else
		usage
	fi
}

function start_thetacrypt {
	info "Starting local Thetacrypt environment"

	start_command="RUST_LOG=info cargo run --release --bin server --"

	for (( id = 0; id < N; id++ )); do
		cmd="${start_command} --config-file local/server_${id}.json --key-file local/keys/keys_${id}.json"
		tmux send-keys -t "${TMUX_SESSION}:${id}" "${cmd}" Enter
	done
}

function stop_thetacrypt {
	info "Stopping local Thetacrypt environment"
	for (( id = 0; id < N; id++ )); do
		tmux send-keys -t "${TMUX_SESSION}:${id}" C-c Enter
	done
}

function usage {
	echo "Usage: ./run_local <start|stop>"
	exit 2
}

function setup_multiplexer {
	if ! tmux list-sessions 2>/dev/null | grep -q "${TMUX_SESSION}"; then
		abort "No tmux session with identifier ${TMUX_SESSEION} found. Create it with \`tmux new -s ${TMUX_SESSION}\` first"
	fi

	window_count=$(tmux list-window -t "${TMUX_SESSION}" | wc -l)
	if (( window_count < N )); then
		delta=$(( N - window_count ))
		info "Spawning ${delta} more windows in tmux session"

		for ((i = 0; i < delta; i++ )); do
			tmux new-window -t "${TMUX_SESSION}"
		done
	fi

	info "tmux session ${TMUX_SESSION} is ready for use"
}

function log {
	msg=$1
	ts=$(date "+%Y-%m-%d %H:%M:%S")

	echo "${ts} ${msg}"
}

function abort {
	msg="[CRITICAL] $1"
	log "${msg}"

	exit 1
}

function info {
	msg="[INFO] $1"
	log "${msg}"
}

main $@
