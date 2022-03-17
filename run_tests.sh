#!/usr/bin/env bash
# Linux setup for running the scripts locally.
# See; https://coverage.readthedocs.io/en/6.3.2/
coverage run -m pytest
coverage report
coverage html
