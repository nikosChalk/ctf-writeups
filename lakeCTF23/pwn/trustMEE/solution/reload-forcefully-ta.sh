#!/bin/bash

pkill -9 grade_ta.so
./load_grade_ca || exit 1
