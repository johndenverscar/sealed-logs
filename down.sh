#!/usr/bin/env bash
# Deletes the kind cluster and everything in it.
set -euo pipefail
kind delete cluster --name sealed
