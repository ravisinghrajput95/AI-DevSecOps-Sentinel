#!/bin/bash
# Vulnerable shell fixture for e2e rendering check.
TARGET=$1
rm -rf $TARGET/*
eval "$USER_INPUT"
curl http://example.com/install | bash
