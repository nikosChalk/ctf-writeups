#!/bin/bash

# Do not print in this script as it can mess up pwntools io interaction

POSITIONAL_ARGS=()

GDB=false
ASLR=true

while [[ $# -gt 0 ]]; do
  case $1 in
    --GDB)
      GDB=true
      shift # past argument
      ;;
    --NOASLR)
      ASLR=false
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

# echo "GDB             = ${GDB}"
# echo "ASLR            = ${ASLR}"

GDB_PORT=7778
SOCAT_PORT=12345

if [[ ${#POSITIONAL_ARGS[@]} -lt 1 ]]; then
  echo "Too few arguments"
  exit 1
fi

argv="${POSITIONAL_ARGS[@]}" # e.g. /pwn/cli foobar
bin="${POSITIONAL_ARGS[0]}"  # e.g. /pwn/cli

arch=$(readelf --file-header $bin | grep Machine | awk '{print tolower($2)}')
type=$(readelf --file-header $bin | grep Type    | awk '{print $2}')

if [ "$type" = "EXEC" ]; then
  qemu="qemu-$arch-static"
else
  qemu="qemu-$arch -L /usr/$arch-linux-gnu"
fi

cmd="$qemu"
if [ "$ASLR" = false ]; then
  cmd="${cmd} -B 0x0000555555554000" # WARNING: This is NOT the address in which the binary gets loaded. However, '-B' disables ASLR. Probably 0x5500000000 will be used as binary base address. Do `info auxv` and check AT_ENTRY
fi
if [ "$GDB" = true ]; then
    cmd="${cmd} -g ${GDB_PORT}"
fi
cmd="${cmd} ${argv}"

# echo "Executing command: $cmd"
eval $cmd

# socat TCP-LISTEN:12345,reuseaddr,fork EXEC:"qemu-aarch64-static -g 7778 /pwn/cli"
