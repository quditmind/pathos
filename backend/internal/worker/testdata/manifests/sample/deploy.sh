#!/bin/sh
# Deliberately flawed sample for the worker-sast fixture tests.
target=$1
rm -rf $target/*
for f in `ls $target`; do
  echo $f
done
eval "echo $2"
