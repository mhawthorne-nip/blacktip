#!/usr/bin/env python3
"""
Minimal setup.py shim for backward compatibility.

Modern installation uses pyproject.toml (PEP 517/518).
This file exists only for compatibility with older tools.

Install with:
    pip install .
    pip install -e .  # Development mode
"""

from setuptools import setup

# All configuration is in pyproject.toml
setup()
