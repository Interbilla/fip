#!/bin/bash
killall openshell-gateway || true
sleep 1
if ss -ltn | grep -q 17670; then
  echo port-busy
  ps -eo pid,comm | grep openshell || true
  exit 1
fi
echo port-free
