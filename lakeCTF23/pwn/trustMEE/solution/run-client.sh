#!/bin/bash

set -e
make all
./load_grade_ca
./grade_ca
