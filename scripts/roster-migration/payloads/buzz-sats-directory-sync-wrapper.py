#!/usr/bin/env python3
"""Compatibility entry point for the standing Buzz channel-sweep timer."""

import os
import sys


TARGET = "/home/victor/.local/libexec/buzz/fleet/roster-5ac44f9f-v1/buzz-sats-directory-sync.py"


os.execv("/usr/bin/python3", ["/usr/bin/python3", TARGET, *sys.argv[1:]])
