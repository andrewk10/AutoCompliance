#!/usr/bin/python3

# Importing logging to safely log sensitive, error or debug info.
import logging
# Importing net_propagation for propagating across the network.
import net_propagation
# Importing strings for use of the external strings resources.
import strings
# Importing sys to make OS calls and use OS level utilities.
import sys
# Importing argparse for command-line option parsing
import argparse


def main():
    parser = argparse.ArgumentParser(description=strings.DESCRIPTION)

    # Adding the file option to the parser.
    parser.add_argument(
                    strings.FILE_OPT_SHORT, strings.FILE_OPT_LONG,
                    help=strings.FILE_HELP)

    # Adding the port option to the parser.
    parser.add_argument(
                    strings.PORT_OPT_SHOT, strings.PORT_OPT_LONG,
                    help=strings.PORT_HELP)

    # Adding the target option to the parser.
    parser.add_argument(
                    strings.TARGET_OPT_SHORT, strings.TARGET_OPT_LONG,
                    help=strings.TARGET_HELP)

    # Adding the username option to the parser.
    parser.add_argument(
                    strings.USERNAME_OPT_SHORT, strings.USERNAME_OPT_LONG,
                    help=strings.USERNAME_HELP)

    # Adding the lan option to the parser.
    parser.add_argument(
                    strings.LAN_OPT_SHORT, strings.LAN_OPT_LONG,
                    help=strings.LAN_HELP)

    # Adding the propagate option to the parser.
    parser.add_argument(
                    strings.PROP_OPT_SHOT, strings.PROP_OPT_LONG,
                    help=strings.PROP_HELP)

    args = parser.parse_args()
    print(args)


if __name__ == "__main__":
    main()
