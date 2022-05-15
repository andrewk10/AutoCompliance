#!/usr/bin/python3

# Author: @andrewk10

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

    # Parsing the arguments and spoofing certain arguments for a forced pass
    arguments = demo_functions.parse_arguments([
        strings.IP_FILE_OPT_SHORT, strings.IP_LIST_SHORT,
        strings.PORT_OPT_SHORT, strings.ALL_PORTS, strings.USERNAME_OPT_SHORT,
        strings.ADMIN, strings.PW_FILE_OPT_SHORT, strings.PWDS_LIST_SHORT])

    assigner = demo_functions.DemoFunctions(arguments)
    assert assigner.assigning_values() is not None

    # Removing certain arguments for a forced fail
    arguments.target = None
    arguments.pw_file = None
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


def test_remove_duplicates_in_list():
    """
    This function tests the remove_duplicates_in_list function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us
    """

    list_with_duplicates = list()
    list_with_duplicates.append(strings.CONSENSUS_MESSAGE_CHANGE_VIEW_REQUEST)
    list_with_duplicates.append(strings.CONSENSUS_MESSAGE_CHANGE_VIEW_REQUEST)
    list_with_duplicates.append(strings.CONSENSUS_MESSAGE_COMMIT)

    list_without_duplicates = list()
    list_without_duplicates.append(strings.
                                   CONSENSUS_MESSAGE_CHANGE_VIEW_REQUEST)
    list_without_duplicates.append(strings.CONSENSUS_MESSAGE_COMMIT)

    assert demo_functions.remove_duplicates_in_list(list_with_duplicates) == \
           list_without_duplicates
