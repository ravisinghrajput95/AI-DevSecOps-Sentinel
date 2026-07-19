#!/bin/bash
# Deliberately vulnerable shell fixture for shellcheck tests.
TARGET=$1
rm -rf $TARGET/*
curl http://example.com/install | bash
echo "deploying to $HOST"
