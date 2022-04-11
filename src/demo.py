#!/usr/bin/python3

# Importing logging to safely log sensitive, error or debug info.
import logging
# Importing net_propagation for propagating across the network.
import net_propagation
# Importing strings for use of the external strings resources.
import strings
# Importing argparse for command-line option parsing
import argparse


def demo():
    """
    This demo function is just for demo purposes.
    """
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

    # Defining ip_list var for the ip list.
    ip_list = []
    # Defining password_list var.
    password_list = []
    # Defining transfer_file_filename var.
    transfer_file_filename = ''
    # Defining username, ports
    target_username = ''
    ports = ''

    if args.target:
        # Extending the ip_list with the ip list.
        ip_list.extend(net_propagation.convert_file_to_list(args.target))

    # Check if the lan option was provided.
    # If so then extend the ip_list.
    if args.lan:
        logging.info(strings.PERFORMING_LOCAL_SCAN)
        ip_list = net_propagation.gathering_local_ips(ip_list)

    if args.file:
        password_list = net_propagation.convert_file_to_list(args.file)

    if args.propagate:
        transfer_file_filename = args.propagate

    if args.port:
        ports = args.port

    if args.u:
        target_username = args.u

    # Removing duplicate entries in the IP address list, can come from
    # combining local scan with given IP addresses in an ip address file for
    # example. This would be a user error, we're just handling that.
    ip_list = list(dict.fromkeys(ip_list))
    # Removing IPs from the IP list that can't be pinged from the host machine
    # of the script.
    ip_list = net_propagation.remove_unreachable_ips(ip_list)
    # Getting a list of ports by splitting the target ports specified by the
    # user on the comma.
    ports = ports.split(strings.COMMA)
    # Cycling through every IP in the IP list...
    for ip in ip_list:
        # And then using all user specified ports against that specific IP...
        for port in ports:
            # Try to spread using services and actions.
            net_propagation.try_action(ip, port, target_username,
                                       password_list, transfer_file_filename,
                                       parser.parse_args())


if __name__ == "__demo__":
    demo()
