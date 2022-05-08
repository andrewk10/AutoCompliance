#!/usr/bin/python3

# Author: @andrewk10

# Importing strings_functions.py for testing.
import strings_functions
# Importing strings for the use of predefined test strings.
import strings


def test_adding_address_to_interface(capfd):
    """
    This function tests the adding_address_to_interface function.
    Should just run straight through no problem hence why all this function
    does is run that function and check what shows up in the console, errors or
    exceptions will fail this test for us as well as a change to the string
    function itself
    :param capfd: Parameter needed to capture log output.
    """
    print(strings_functions.adding_address_to_interface(strings.TEST_IP,
                                                        strings.LOOPBACK))
    out, err = capfd.readouterr()
    assert out == strings.ADDING + strings.SPACE + strings.TEST_IP + \
        strings.SPACE + strings.FROM_INTERFACE + strings.SPACE + \
        strings.LOOPBACK + strings.INTERFACE_SUBNET + "\n"


def test_cat_file(capfd):
    """
    This function tests the cat_file function. Should just run straight through
    no problem hence why all this function does is run that function and check
    what shows up in the console, errors or exceptions will fail this test for
    us as well as a change to the string function itself
    :param capfd: Parameter needed to capture log output.
    """
    print(strings_functions.cat_file(strings.FILE))
    out, err = capfd.readouterr()
    assert out == strings.CAT + strings.SPACE + strings.FILE + "\n"


def test_checking_ip_reachable(capfd):
    """
    This function tests the checking_ip_reachable function. Should just run
    straight through no problem hence why all this function does is run that
    function and check what shows up in the console, errors or exceptions will
    fail this test for us as well as a change to the string function itself
    :param capfd: Parameter needed to capture log output.
    """
    print(strings_functions.checking_ip_reachable(strings.TEST_IP))
    out, err = capfd.readouterr()
    assert out == strings.IS_IP_REACHABLE + strings.SPACE + strings.TEST_IP + \
           "\n"


def test_ip_reachability(capfd):
    """
    This function tests the ip_reachability function. Should just run straight
    through no problem hence why all this function does is run that function
    and check what shows up in the console for both a reachable and
    unreachable IP, errors or exceptions will fail this test for us as well as
    a change to the string function itself
    :param capfd: Parameter needed to capture log output.
    """
    permutations = [True, False]
    for permutation in permutations:
        print(strings_functions.ip_reachability(strings.TEST_IP, permutation))
        out, err = capfd.readouterr()
        if permutation:
            assert out == strings.TEST_IP + strings.SPACE + \
                   strings.WAS_REACHABLE + strings.FULL_STOP + "\n"
        else:
            assert out == strings.TEST_IP + strings.SPACE + \
                   strings.WAS_NOT_REACHABLE + strings.FULL_STOP + "\n"
