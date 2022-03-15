#!/usr/bin/python3

from src import strings

"""
 - Importing strings for common string resources.
"""

"""
===PLEASE READ===
String functions and constants are organised alphabetically. Every string
function has a block comment explaining what it does and where it's used and
every string constant has a comment describing its use. These strings are
exclusively used in tests.
"""

# Admin user string.
ADMIN = "admin"

# All ports list, for utilising all services in the scripts.
ALL_PORTS = "22,23,25,80"

# Name of the test text file, prepended with src/ for Pytest to work.
FILE = "src/test_files/test_file.txt"

# Name of the test IP list file, prepended with src/ for Pytest to work.
IP_LIST = "src/test_files/test_ip_list.txt"

# Lines to check from the test file.
LINES = ["Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
         "do eiusmod tempor", "incididunt ut labore et dolore magna "
         "aliqua. Ut enim ad minim veniam, quis",
         "nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
         "commodo consequat.", "Duis aute irure dolor in reprehenderit "
         "in voluptate velit esse cillum dolore",
         "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
         " proident, sunt", "in culpa qui officia deserunt mollit anim id"
         " est laborum."]

# Root user string.
ROOT = "root"

# List of dummy passwords
PASSWORDS_LIST = "password_list.txt"

# A string just for tests.
RANDOM_STRING = "tests"

# SSH and Telnet port specification
SSH_AND_TELNET_PORTS = "22,23"


def arguments_set_one():
    """
    This function contains the first set of arguments used for testing
    purposes. This runs the script against all services and four ports
    :return : The arguments themselves
    """
    return strings.ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST, \
        strings.ARGUMENT_PORTS, ALL_PORTS, strings.ARGUMENT_USERNAME, \
        ADMIN, strings.ARGUMENT_PWS_FILENAME, PASSWORDS_LIST


def arguments_set_two():
    """
    This function contains the second set of arguments used for testing
    purposes. This just runs the scripts against one port / service
    :return : The arguments themselves
    """
    return strings.ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST, \
        strings.ARGUMENT_PORTS, strings.SSH_PORT, \
        strings.ARGUMENT_USERNAME, ROOT, strings.ARGUMENT_PWS_FILENAME,\
        PASSWORDS_LIST


def arguments_set_three():
    """
    This function contains the third set of arguments used for testing
    purposes, except this time it propagates a specific file over SSH
    :return : The arguments themselves
    """
    return strings.ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST, \
        strings.ARGUMENT_PORTS, strings.SSH_PORT, \
        strings.ARGUMENT_USERNAME, ROOT, strings.ARGUMENT_PWS_FILENAME, \
        PASSWORDS_LIST, strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE, FILE


def arguments_set_four():
    """
    This function contains the fourth set of arguments used for testing
    purposes, except this time we're running the automated propagation feature
    over SSH and Telnet
    :return : The arguments themselves
    """
    return strings.ARGUMENT_SCAN_LOCAL_NETWORKS, strings.ARGUMENT_PORTS, \
        SSH_AND_TELNET_PORTS, strings.ARGUMENT_USERNAME, ROOT, \
        strings.ARGUMENT_PWS_FILENAME, PASSWORDS_LIST, \
        strings.ARGUMENT_PROPAGATE
