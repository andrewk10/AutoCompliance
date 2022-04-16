#!/usr/bin/env bash
# Pytest local run with coverage
# See; https://coverage.readthedocs.io/en/6.3.2/
coverage run -m pytest -vv
coverage report
coverage html