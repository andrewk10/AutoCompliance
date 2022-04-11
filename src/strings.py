#!/usr/bin/python3

# The adding string.
ADDING = "Adding"

# Admin user string.
ADMIN = "admin"

# All ports list, for utilising all services in the scripts.
ALL_PORTS = "22,23,25,80"

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

# Just a little arrow for CLI output.
ARROW = "->"

# Prompt to let people know arguments are being assigned for testing.
ASSIGNING_ARGUMENTS = "Assigning arguments as part of test"

# Just the '@' symbol
AT_SYMBOL = "@"

# String to describe the username argument under help
A_USERNAME = "A username"

# Blank String
BLANK_STRING = ''

# Letting the user know we can't read an IP list from a specific file.
CAN_NOT_READ_IP_LIST = "IP list cannot be read from filename:"

# cat command
CAT = "cat"

# Let the user know there's something wrong with the file paths provided.
CHECK_FILE_PATHS = "There's something wrong with the file paths provided, " \
                   "please review them and try again."

# A string that states that the IP and port pair is closed.
CLOSED_IP_PORT_PAIR = "This IP address and port pair is closed"

# A string that just denotes the use of a colon, same "idea" as above.
COLON = ":"

# A string that just denotes the use of a comma, same "idea" as above.
COMMA = ","

# The main filename
DEMO_SCRIPT_FILENAME = "demo.py"

# The demo script path.
DEMO_SCRIPT_PATH = "./demo.py"

# A string that states a script wasn't propagated.
DO_NOT_PROPAGATE = "Requirement to propagate script not specified, skipping..."

# A string that states a file wasn't transferred.
DO_NOT_TRANSFER = "Requirement to transfer file not specified, skipping..."

# Just three dots at the end of a sentence.
ELLIPSES = "..."

# A string for specifying encoding for ascii.
ENCODE_ASCII = "ascii"

# A string which specifically states something is example usage.
EXAMPLE_USAGE = "Example usage:"

# An exiting prompt.
EXITING = "Exiting..."

# Prompts the user that values couldn't be assigned
FAILED_ASSIGNING_VALUES = "Failed assigning values (maybe null)"

# Fetching IP for a given interface message
FETCHING_INTERFACE_IPS = "Fetching IPs for interface"

# Prompts the user that their fetching the local interface list.
FETCHING_LOCAL_INTERFACE_LIST = "Fetching local interface list..."

# Name of the test text file, prepended with src/ for Pytest to work.
FILE = "src/test_files/file.txt"

# Lets the user know a file doesn't exist.
FILE_DOES_NOT_EXIST = "A specified file does not exist"

# Lets the user know that a file is present on the host.
FILE_PRESENT_ON_HOST = "A file is already present on this host:"

# String for the help output.
FILENAME_LIST_IP_ADDRESSES = "Filename for a file containing a list of " \
                             "target IP addresses"

# String for forcing a fail for tests.
FORCE_FAIL = "This Should Work"

# Lets the user know there's an open port on a specific IP address.
FOUND_OPEN_IP_PORT_PAIR = "Found an open IP address and port pair"

# Just simply says "from interface"
FROM_INTERFACE = "from interface"

# Full stop string, memory saving again, reducing redundant assigns.
FULL_STOP = "."

# There's a problem with parsing a file with a given filename.
FILENAME_PROCESSING_ERROR = "One of the filenames are invalid"

# String for defining the passwords filename argument under help.
FILENAME_PWS_FILE = "Filename for a file containing a list of passwords"

# Greater than symbol.
GREATER_THAN = ">"

# The help string for the propagation argument definition in help output.
HELP_STRING_PROPAGATION = "Propagates the script onto available devices and " \
                          "executes the script using the given command"

# Home directory string.
HOME_DIR = ":~/"

# HTTPS String for start of URLs.
HTTPS_STRING = "https://"

# Letting the user know a propagation action had failed.
IMPOSSIBLE_ACTION = "It was impossible to bruteforce this IP address and port"

# Specifying that something is from an interface's subnet.
INTERFACE_SUBNET = "'s subnet."

# Letting the user know a specified IP file could not be found.
IP_FILENAME_NOT_FOUND = "Could not find the specified IP file"

# Name of the test IP list file, prepended with src/ for Pytest to work.
IP_LIST = "src/test_files/ip_list.txt"

# Name of the short test IP list file, prepended with src/ for Pytest to work.
IP_LIST_SHORT = "src/test_files/ip_list_short.txt"

# Let the suse know that we're checking to see if the IP address is reachable.
IS_IP_REACHABLE = "Checking if the following ip address is reachable:"

# The less than symbol.
LESS_THAN = "<"

# Lines to check from the test file.
LINES = ["Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed "
         "do eiusmod tempor", "incididunt ut labore et dolore magna "
         "aliqua. Ut enim ad minim veniam, quis",
         "nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
         "commodo consequat.", "Duis aute irure dolor in reprehenderit "
         "in voluptate velit esse cillum dolore",
         "eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non"
         " proident, sunt", "in culpa qui officia deserunt mollit anim id"
         " est laborum."]

# The string that defines the local scan argument in the help output.
LOCAL_SCAN_STRING_HELP = "Scans the lan across all interfaces and " \
                         "creates/adds to the list of target IP addresses"

# Login PHP string, generally used with web logins.
LOGIN_PHP = "/login.php"

# The login prompt a user usually sees with SSH.
LOGIN_PROMPT = "login:"

# Login to string, another string building constant.
LOGIN_TO = "login to"

# The typical ID of the loopback interface.
LOOPBACK = "lo"

# The main function call.
MAIN = "main()"

# A string to let the user know a necessary argument is missing.
MISSING_ARGUMENT = "Missing a mandatory argument, ensure arguments are used " \
                   "correctly"

# Netcat listener, with a specified port, the command.
NETCAT_LISTENER_PORT_COMMAND = "nc -l -p"

# Netcat writer with a 3-second timeout time, command.
NETCAT_WRITER_COMMAND = "nc -w 3"

# The name of the net propagation script.
NET_PROPAGATION = "src/net_propagation.py"

# Newline character, mostly used to mimic an enter key press.
NEWLINE = "\n"

# Two newline and tab special characters.
NEWLINE_NEWLINE_TAB = "\n\n\t"

# The newline and tab special characters.
NEWLINE_TAB = "\n\t"

# Just the numerical form of the number one, again, memory preservation.
ONE = "1"

# Password prompt for SSH.
PASSWORD_PROMPT = "Password:"

# Password prompt for web logins, rather the post ID really.
PASSWORD_PROMPT_WEB = "password:"

# List of dummy passwords
PWDS_LIST = "src/test_files/passwords_list.txt"

# Shorter list of dummy passwords
PWDS_LIST_SHORT = "src/test_files/passwords_list_short.txt"

# Parameters string for help test.
PARAMETERS = "Parameters:"

# Parameters were used incorrectly, so we're telling the user what to do.
PARAMETER_MISUSE = "Parameter misuse, check help text below"

# Letting the user know we're performing a local scan.
PERFORMING_LOCAL_SCAN = "Performing local scan, this might take a while so " \
                        "grab a coffee..."

# The ping command.
PING = "ping"

# The argument for ping which specifies the number of packets sent.
PING_ARGUMENT = "-c"

# String for the help text.
PORTS_TO_SCAN = "Ports to scan on the target host"

# A string just for tests.
RANDOM_STRING = "tests"

# Root user string.
ROOT = "root"

# RSA specific password prompt.
RSA_AND_PROMPT = "Please type in this password below and say yes to any " \
                 "RSA key prompts: "

# A different password prompt following the previous one.
RSA_PROMPT_AGAIN = "Please type in this password again: "

# The error when an SSH command has been tampered with.
SANITATION_FAILED = "SSH command did not pass sanitation checks"

# SCP Command String.
SCP_COMMAND = "scp -P"

# Specifies that the script has been propagated over a port (use debug for
# specific port number).
SCRIPT_PROPAGATED = "Script propagated over this port"

# Specifies that the script hasn't been propagated over a port.
SCRIPT_NOT_PROPAGATED = "Script couldn't be propagated over this port"

# Just a space, yep, really.
SPACE = " "

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

# Test IP addresses.
TEST_IP = "192.168.1.1"

# The string used for the touch command
TOUCH_COMMAND = "touch"

# Letting the user know a file couldn't be transferred over SSH default port.
TRANSFER_FAILURE_SSH = "File couldn't be transferred over port 22 / SSH"

# Letting the user know a file could be transferred over port 22 / SSH default
# ports.
TRANSFER_SUCCESS_SSH = "File transferred over port 22 / SSH"

# Unsuccessful statement to be used with services and actions.
UNSUCCESSFUL = "Unsuccessful"

USERNAME_IN_PWS = "using the specified username with a password in the " \
                  "passwords file."

# The username prompt that comes with web login POST requests.
USERNAME_PROMPT_WEB = "username:"

# Letting the user know something was found.
WAS_FOUND = "was found."

# A string stating that something was not reachable
WAS_NOT_REACHABLE = "was not reachable"

# A string stating that something was reachable
WAS_REACHABLE = "was reachable"

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

# Letting the user know about a working username and password.
WORKING_USERNAME_PASS = "A working username and password for"

# This is the program description for the cli help menu.
DESCRIPTION = "Automating the Implementation of a " \
              "Cybersecurity Governance, Risk and " \
              "Compliance Programme using Distributed " \
              "Ledger Technologies"

# Help text and option name for the file option.
FILE_OPT_SHORT = "-f"
FILE_OPT_LONG = "--file"
FILE_HELP = "Filename for a file containing a list of passwords"

# Help text and option name for the port option.
PORT_OPT_SHOT = "-p"
PORT_OPT_LONG = "--port"
PORT_HELP = "Ports to scan on the target host"

# Help text and option name for the target option.
TARGET_OPT_SHORT = "-t"
TARGET_OPT_LONG = "--target"
TARGET_HELP = "Filename for a file containing a list of target IP addresses"

# Help text and option name for the username option.
USERNAME_OPT_SHORT = "-u"
USERNAME_OPT_LONG = "-u"
USERNAME_HELP = "A Username"

# Help text and option name for the lan scan option.
LAN_OPT_SHORT = "-L"
LAN_OPT_LONG = "--lan"
LAN_HELP = "Scans the lan across all interfaces and " \
            "creates/adds to the list of target IP addresses"

# Help text and option name for the propagate option.
PROP_OPT_SHOT = "-P"
PROP_OPT_LONG = "--propagate"
PROP_HELP = "Propagates the script onto available devices " \
            "and executes the script using the given command"


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
    return ADDING + SPACE + str(specific_address) + SPACE + \
        FROM_INTERFACE + SPACE + str(interface) + INTERFACE_SUBNET


def arguments_sets(selection):
    """
    This function contains the all sets of arguments used for testing
    purposes
    :param selection: The argument being called from the function
    :return : The argument selected itself.
    """
    arguments = {
        # This runs the script against all services and four ports
        0: [ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST_SHORT, ARGUMENT_PORTS,
            ALL_PORTS, ARGUMENT_USERNAME, ADMIN, ARGUMENT_PWS_FILENAME,
            PWDS_LIST_SHORT],
        # This just runs the scripts against one port / service
        1: [ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST_SHORT, ARGUMENT_PORTS,
            SSH_PORT, ARGUMENT_USERNAME, ROOT, ARGUMENT_PWS_FILENAME,
            PWDS_LIST_SHORT],
        # This propagates a specific file over SSH
        2: [ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST_SHORT, ARGUMENT_PORTS,
            SSH_PORT, ARGUMENT_USERNAME, ROOT, ARGUMENT_PWS_FILENAME,
            PWDS_LIST_SHORT, ARGUMENT_SPECIFIC_PROPAGATION_FILE, FILE],
        # This is running the automated propagation feature over SSH.
        3: [ARGUMENT_SCAN_LOCAL_NETWORKS, ARGUMENT_PORTS, SSH_PORT,
            ARGUMENT_USERNAME, ROOT, ARGUMENT_PWS_FILENAME, PWDS_LIST_SHORT,
            ARGUMENT_PROPAGATE],

        # This fails to run the script against all services and four ports
        # because the passwords file filename is invalid.
        4: [ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST_SHORT, ARGUMENT_PORTS,
            ALL_PORTS, ARGUMENT_USERNAME, ADMIN, ARGUMENT_PWS_FILENAME,
            FORCE_FAIL],
        # This fails to run the scripts against one port / service because the
        # OP list filename is invalid.
        5: [ARGUMENT_IP_ADDRESS_FILENAME, FORCE_FAIL, ARGUMENT_PORTS,
            SSH_PORT, ARGUMENT_USERNAME, ROOT, ARGUMENT_PWS_FILENAME,
            PWDS_LIST_SHORT],
        # This fails the propagation of a specific file over SSH because
        # parameter misuse.
        6: [ARGUMENT_IP_ADDRESS_FILENAME, IP_LIST_SHORT, PWDS_LIST_SHORT,
            SSH_PORT, ARGUMENT_USERNAME, ROOT, ARGUMENT_PWS_FILENAME,
            PWDS_LIST_SHORT, ARGUMENT_SPECIFIC_PROPAGATION_FILE, FILE],
        # This fails in general as no arguments are specified.
        7: [FORCE_FAIL, FORCE_FAIL, FORCE_FAIL, FORCE_FAIL, FORCE_FAIL,
            FORCE_FAIL, FORCE_FAIL, FORCE_FAIL],
    }
    return arguments.get(selection, None)


def cat_file(filename):
    """
    This function creates a command for concatenating a specific file
    :param filename: The filename of the file we want to touch
    :return "cat " + filename: The completed cat command
    """
    return CAT + SPACE + filename


def checking_ip_reachable(ip):
    """
    This function creates a string that describes the availability of a machine
    on a specific IP address
    :param ip: The specific IP address
    :return "Checking if the following ip address is reachable: " + str(ip):
    The string in question
    """
    return IS_IP_REACHABLE + SPACE + str(ip)


def connection_status(service, ip, port, status):
    """
    This function creates the connection status string dependent
    on the context given by the arguments passed into it.
    """
    return str(status) + SPACE + str(service) + SPACE + LOGIN_TO + SPACE + \
        str(ip) + COLON + str(port) + SPACE + USERNAME_IN_PWS


def fetching_ips_for_interface(interface):
    """
    This function generates the string for fetching the IPs for a specific
    interface
    :param interface: The interface we're fetching IPs on
    :return "Fetching IPs for interface " + str(interface) + "...": The string
    in question
    """
    return FETCHING_INTERFACE_IPS + SPACE + str(interface) + ELLIPSES


def file_present_on_host(ip):
    """
    This function generates the string for a file already present on a host
    :param ip: The host itself
    :return "A file is already present on this host: " + str(ip): The string
    in question
    """
    return FILE_PRESENT_ON_HOST + SPACE + str(ip)


def scp_command_string(port, username, target_ip, filename):
    """
    This function creates and SSH copy string for an OS command
    :param port: Port over which we are running the SSH copy
    :param username: The username for the SSH login
    :param target_ip: The IP address of the machine we are copying too
    :param filename: The name of the file to be copied across by SSH
    :return: The SSH copy command
    """
    return SCP_COMMAND + SPACE + str(port) + SPACE + filename + SPACE + \
        username + AT_SYMBOL + target_ip + HOME_DIR


def touch_file(filename):
    """
    This function creates a command for touching a specific file
    :param filename: The filename of the file we want to touch
    :return: The completed touch command
    """
    return TOUCH_COMMAND + SPACE + filename


def ip_list_not_read(filename):
    """
    This function returns the error for an ip list that can't be generated from
    a particular filename
    :param filename: The filename of the file that can't have an ip list
    derived from it
    :return: The string in question
    """
    return CAN_NOT_READ_IP_LIST + SPACE + filename


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
        return str(ip) + SPACE + WAS_REACHABLE + FULL_STOP
    return str(ip) + SPACE + WAS_NOT_REACHABLE + FULL_STOP


def netcat_listener(port, filename):
    """
    This function will create a netcat listener on the device we have a netcat
    link to
    :param port: The port on which the netcat listener will operate
    :param filename: The filename of the file we're moving using the listener
    parameter
    :return: The string in question
    """
    return NETCAT_LISTENER_PORT_COMMAND + SPACE + str(port) + SPACE + \
        GREATER_THAN + SPACE + filename


def netcat_writer(ip, port, filename):
    """
    This function will create a netcat writer to write a file to a device we
    have a netcat link to
    :param ip: Machine with the netcat listener we are writing to
    :param port: The port on which the netcat writer will operate
    :param filename: The filename of the file we're moving using the writer
    parameter
    :return: The string in question
    """
    return NETCAT_WRITER_COMMAND + SPACE + str(ip) + SPACE + str(port) + \
        SPACE + LESS_THAN + SPACE + filename


def help_output():
    """
    This is the help output for when the user passes in the help parameter
    :return: The output itself.
    """
    return PARAMETERS + NEWLINE_TAB + ARGUMENT_IP_ADDRESS_FILENAME + SPACE + \
        ARROW + SPACE + FILENAME_LIST_IP_ADDRESSES + NEWLINE_TAB + \
        ARGUMENT_PORTS + SPACE + ARROW + SPACE + PORTS_TO_SCAN + \
        NEWLINE_TAB + ARGUMENT_USERNAME + SPACE + ARROW + SPACE + \
        A_USERNAME + NEWLINE_TAB + ARGUMENT_PWS_FILENAME + SPACE + ARROW + \
        SPACE + FILENAME_PWS_FILE + NEWLINE_TAB + \
        ARGUMENT_SCAN_LOCAL_NETWORKS + SPACE + ARROW + SPACE + \
        LOCAL_SCAN_STRING_HELP + NEWLINE_TAB + ARGUMENT_PROPAGATE + SPACE + \
        ARROW + SPACE + HELP_STRING_PROPAGATION + NEWLINE + EXAMPLE_USAGE + \
        NEWLINE_TAB + DEMO_SCRIPT_PATH + SPACE + \
        ARGUMENT_IP_ADDRESS_FILENAME + SPACE + IP_LIST + SPACE + \
        ARGUMENT_PORTS + SPACE + ALL_PORTS + SPACE + ARGUMENT_USERNAME + \
        SPACE + ADMIN + SPACE + ARGUMENT_PWS_FILENAME + SPACE + PWDS_LIST + \
        NEWLINE_NEWLINE_TAB + DEMO_SCRIPT_PATH + \
        ARGUMENT_IP_ADDRESS_FILENAME + SPACE + IP_LIST + SPACE + \
        ARGUMENT_PORTS + SPACE + SSH_PORT + SPACE + ARGUMENT_USERNAME + \
        SPACE + ROOT + SPACE + ARGUMENT_PWS_FILENAME + SPACE + PWDS_LIST


def run_script_command():
    """
    This function will run the propagation script on another target machine
    over any service
    :return: The command itself
    """
    return DEMO_SCRIPT_PATH + SPACE + ARGUMENT_SCAN_LOCAL_NETWORKS + SPACE + \
        ARGUMENT_PORTS + SPACE + SSH_PORT + SPACE + ARGUMENT_USERNAME + \
        SPACE + ROOT + SPACE + ARGUMENT_PWS_FILENAME + PWDS_LIST + SPACE + \
        ARGUMENT_PROPAGATE


def web_login_url(ip, port):
    """
    This function will build the web login url string
    :param ip: The IP of the machine running the web service
    :param port: The port the web service is running on
    :return: The string itself
    """
    return HTTPS_STRING + ip + COLON + port + LOGIN_PHP


def working_username_password(service):
    """
    This function will build a string for a working username and password given
     a specific service
    :param service: Service for which there is a working username and password
    combination
    :return: The string itself
    """
    return WORKING_USERNAME_PASS + SPACE + str(service) + SPACE + WAS_FOUND
