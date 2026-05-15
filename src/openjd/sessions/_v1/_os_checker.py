# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
import sys

def is_posix() -> bool:
    return sys.platform != "win32"

def is_windows() -> bool:
    return sys.platform == "win32"

def check_os() -> str:
    return "win32" if is_windows() else "posix"
