#!/usr/bin/python3

"""
===PLEASE READ===
String functions and constants are organised alphabetically. Every string
function has a block comment explaining what it does and where it's used and
every string constant has a comment describing its use.
"""

EXITING = "Exiting..."
PERFORMING_LOCAL_SCAN = "Performing local scan, this might take a while so " \
                        "grab a coffee..."
PLS_HELP = "Parameters:\n\t-t -> Filename for a file containing a list of " \
           "target IP addresses\n\t-p -> Ports to scan on the target host" \
           "\n\t-u -> A username\n\t-f -> Filename for a file containing " \
           "a list of passwords\n\t-L -> Scans the lan across all " \
           "interfaces and creates/adds to the list of target IP addresses" \
           "\n\t-P -> Propagates the script onto available devices and " \
           "executes the script using the given command\nExample usage:\n" \
           "\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin " \
           "-f my_password_list.txt\n\n\t./net_attack.py -t ip_list.txt " \
           "-p 22 -u root -f passwords.txt"


def connection_status(service, ip, port, status):
    """
    This function creates the connection status string dependent
    on the context given by the arguments passed into it.
    """
    string = str(status) + " " + str(service) + " login to " + str(ip) + ":" \
        + str(port) \
        + " using the specified username with a password in the passwords" \
          " file."
    return string


def filename_processing_error(filename):
    string = "!!!ERROR: SOMETHING WENT WRONG WHEN PROCESSING THE FILENAME: " \
             + filename + "!!!"
    return string


def ip_list_not_read(filename):
    """
    This function returns the error for an ip list that can't be generated from
    a particular filename
    :param filename: The filename of the file that can't have an ip list
    derived from it
    :return string: The string in question.
    """
    string = "IP list cannot be read from filename: " + filename
    return string
