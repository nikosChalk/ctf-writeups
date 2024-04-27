#!/bin/bash

while :
do
  python solution.py "$@"
  if [ $? -eq 0 ]; then
    break
  fi
done
