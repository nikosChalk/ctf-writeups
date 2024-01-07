#!/bin/bash

set -e
./load_grade_ca
gdb /opt/OpenTee/bin/opentee-engine `pgrep grade_ta.so` -x ./script.gdb
