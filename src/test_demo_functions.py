#!/usr/bin/python3

# Import demo_functions to test the demo specific functionality.
import demo_functions
# Importing strings for use of the external strings resources.
import strings
# Importing strings_functions for string building functions.
import strings_functions
# Importing argparse for mocking argument parsing.
import argparse


def test_assigning_values():
    """
    This function tests the assigning_values function in the net_propagation
    script. It uses example arguments to do this stored in strings.py, but
    before it does that the bad path is checked by passing in a single argument
    with no value to get a runtime error.
    """

    # Argument parser for handling arguments.
    parser = argparse.ArgumentParser(description=strings.DESCRIPTION)
    # Adding the target  file option to the parser.
    parser.add_argument(
        strings.IP_FILE_OPT_SHORT, strings.IP_FILE_OPT_LONG,
        dest='target', help=strings.IP_FILE_HELP, type=str)
    # Adding the username option to the parser.
    parser.add_argument(
        strings.USERNAME_OPT_SHORT, strings.USERNAME_OPT_LONG,
        dest='username', help=strings.USERNAME_HELP, type=str)
    # Adding the password file option to the parser.
    parser.add_argument(
        strings.PW_FILE_OPT_SHORT, strings.PW_FILE_OPT_LONG,
        dest="password_file", help=strings.PW_FILE_HELP, type=str)
    # Adding the port option to the parser.
    parser.add_argument(
        strings.PORT_OPT_SHORT, strings.PORT_OPT_LONG,
        dest='ports', help=strings.PORT_HELP, type=str)
    # Adding the lan option to the parser.
    parser.add_argument(
        strings.LAN_OPT_SHORT, strings.LAN_OPT_LONG,
        dest='lan', help=strings.LAN_HELP, type=str)
    # Adding the propagate option to the parser.
    parser.add_argument(
        strings.PROP_OPT_SHORT, strings.PROP_OPT_LONG,
        dest='propagate', help=strings.PROP_HELP, type=str)
    # Adding the transfer file option to the parser.
    parser.add_argument(
        strings.PROP_FILE_OPT_SHORT, strings.PROP_FILE_OPT_LONG,
        dest='propagate_file', help=strings.PROP_FILE_HELP, type=str)

    # Parsing the arguments.
    arguments = parser.parse_args()

    # Spoofing certain arguments for a forced pass
    arguments.target = strings.IP_LIST_SHORT
    arguments.ports = strings.ALL_PORTS
    arguments.username = strings.ADMIN
    arguments.password_file = strings.PWDS_LIST_SHORT
    assigner = demo_functions.DemoFunctions(arguments)
    assert assigner.assigning_values() is not None

    # Removing certain arguments for a forced fail
    arguments.target = None
    arguments.password_file = None
    assigner = demo_functions.DemoFunctions(arguments)
    assert assigner.assigning_values() is None


def test_exit_and_show_instructions(capfd):
    """
    This function tests the exit_and_show_instructions function.
    Should just run straight through no problem hence why all this function
    does is run that function and check what shows up in the console, errors or
    exceptions will fail this test for us
    :param capfd: Parameter needed to capture log output.
    """
    demo_functions.exit_and_show_instructions()
    out, err = capfd.readouterr()
    assert out == strings_functions.help_output() + "\n" + strings.EXITING + \
           "\n"
