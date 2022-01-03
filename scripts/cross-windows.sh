#!/usr/bin/env bash

set -Eeuo pipefail
trap cleanup SIGINT SIGTERM ERR EXIT

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
version="1.0.0"
#supported_targets=["x86_64-pc-windows-gnu", "x86-pc-windows-gnu"]
usage() {
  cat << EOF # remove the space between << and EOF, this is due to web plugin issue
Usage: $(base-program "${BASH_SOURCE[0]}") [-h] [-r] -t target_name

Run this program in a WSL 2 installation. The windows host MUST have docker installed and configured to interface with WSL 2
This will produce a windows binary which can be used.
See https://tomger.eu/posts/cross-compile-rust-wsl/ for help in setting up WSL for this task

Available options:

-h, --help      Print this help and exit
-t, --target    the toolchain to target (default=x86_64-pc-windows-gnu)
-r, --release   Should we compile in release mode (default=false)
EOF
  exit
}

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
  # script cleanup here
}

setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW=''
  fi
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "$msg"
  exit "$code"
}

parse_params() {
  # default values of variables set from params
  release=false
  target='x86_64-pc-windows-gnu'

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    --no-color) NO_COLOR=1 ;;
    -r | --release) release=true ;;
    -t | --target)
      target="${2-}"
      shift
      ;;
    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  args=("$@")
  # shellcheck disable=SC2076

  #if [[ ! " ${supported_targets[*]} " =~ "${target}" ]]
  #then
   #msg "${GREEN} Supported target:${NOFORMAT}"
  #else
    #msg "${RED} Unsupported target:${NOFORMAT}"
    #die
  #fi


  return 0
}

parse_params "$@"
setup_colors

# script logic here

msg "${GREEN}Avrio build utility (v$version):${NOFORMAT}"
msg "Using options:"
msg "- target: ${target}"
msg "- release: ${release}"

msg "Installing cross tool"
cargo install cross
msg "Cross installed, beginning build"
if [ "$release" = true ]
then
  cross build --target "${target}" --release
else
  cross build --target "${target}"
fi

