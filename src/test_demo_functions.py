#!/usr/bin/python3

# Import demo_functions to test the demo specific functionality.
import demo_functions
# Importing strings for use of the external strings resources.
import strings
# Importing strings_functions for string building functions.
import strings_functions


def test_assigning_values():
    """
    This function tests the assigning_values function in the net_propagation
    script. It uses example arguments to do this stored in strings.py, but
    before it does that the bad path is checked by passing in a single argument
    with no value to get a runtime error.
    """
    num_arguments = 8
    happy_path_range = 4
    for arguments_selection in range(num_arguments):
        assigner = demo_functions.DemoFunctions(
            strings_functions.arguments_sets(arguments_selection))
        if arguments_selection < happy_path_range:
            assert assigner.assigning_values() is not None
        else:
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
