#!/usr/bin/env bash
# Pytest local run with coverage
# See; https://coverage.readthedocs.io/en/6.3.2/
coverage run -m pytest
# For more verbose testing uncomment the following line, you can also comment
# the line above to avoid running the tests twice, bear in mind running verbose
# testing can break some argument tests.
# coverage run -m pytest -vv
coverage report
coverage html