#!/usr/bin/python3

# A string that just states "Adding".
ADDING = "Adding"

# Admin user string.
ADMIN = "admin"

# All ports list, for utilising all services in the scripts.
ALL_PORTS = "22,23,25,80"

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

# The demo filename
DEMO_SCRIPT_FILENAME = "demo.py"

# The demo script path.
DEMO_SCRIPT_PATH = "./demo.py"

# This is the program description for the cli help menu.
DESCRIPTION = "Automating the Implementation of a " \
              "Cybersecurity Governance, Risk and " \
              "Compliance Programme using Distributed " \
              "Ledger Technologies"

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

# Help text for... the help.
HELP_HELP = "Guidance regarding how to utilise the demo back-end"

# Short option name for help.
HELP_OPT_SHORT = "-h"

# Option name for help.
HELP_OPT_LONG = "--help"

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

# Help text for the target IP option.
IP_FILE_HELP = "Filename for a file containing a list of target IP " \
                   "addresses"

# Short option name for the target IP option.
IP_FILE_OPT_SHORT = "-t"

# Option name for the target IP option.
IP_FILE_OPT_LONG = "--target"

# Letting the user know a specified IP file could not be found.
IP_FILENAME_NOT_FOUND = "Could not find the specified IP file"

# Name of the test IP list file, prepended with src/ for Pytest to work.
IP_LIST = "src/test_files/ip_list.txt"

# Name of the short test IP list file, prepended with src/ for Pytest to work.
IP_LIST_SHORT = "src/test_files/ip_list_short.txt"

# Let the user know that we're checking to see if the IP address is reachable.
IS_IP_REACHABLE = "Checking if the following ip address is reachable:"

# Help text for the LAN scan option.
LAN_HELP = "Scans the lan across all interfaces and " \
            "creates/adds to the list of target IP addresses"

# Short option name for the LAN scan option.
LAN_OPT_SHORT = "-L"

# Option name for the LAN scan option.
LAN_OPT_LONG = "--lan"

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

# "Login to" string, another string building constant.
LOGIN_TO = "login to"

# The typical ID of the loopback interface.
LOOPBACK = "lo"

# The typical ID of the loopback interface.
LOOPBACK_IP = "127.0.0.1"

# The typical IP of the loopback interface as a list for testing.
LOOPBACK_IP_AS_LIST = ["127.0.0.1"]

# The typical IP of the loopback interface as a list for testing, second
# iteration as the first iteration on the full run of the test suite breaks?
# Weird.
LOOPBACK_IP_AS_LIST_REMOVE = ["127.0.0.1"]

# The typical IP of the loopback interface as a list for testing.
LOOPBACK_AND_FAIL_IP_AS_LIST = ["127.0.0.1", "10.255.255.254"]

# The main script.
MAIN_SCRIPT = "./main.py"

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

# Short option name for the password file option.
PW_FILE_OPT_SHORT = "-f"

# Option name for the password file option.
PW_FILE_OPT_LONG = "--file"

# Help text for the password file option.
PW_FILE_HELP = "Filename for a file containing a list of passwords"

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

# The error for when the ping command can not be tested, so instead we must
# default to removing an IP address
PING_CMD_NOT_FOUND = "The ping command is not available, defaulting to " \
                     "removing IP"

# Short option name for the port option.
PORT_OPT_SHORT = "-p"

# Option name for the port option.
PORT_OPT_LONG = "--port"

# Help text for the port option.
PORT_HELP = "Ports to scan on the target host"

# String for the help text.
PORTS_TO_SCAN = "Ports to scan on the target host"

# Help text for the propagate option.
PROP_HELP = "Propagates the script onto available devices " \
            "and executes the script using the given command"

# Option name for the propagate option.
PROP_OPT_LONG = "--propagate"

# Short option name for the propagate option.
PROP_OPT_SHORT = "-P"

# Help text for the propagate option.
PROP_FILE_HELP = "Propagates the provided file onto available devices"

# Option name for propagate a file option.
PROP_FILE_OPT_LONG = "--deliver"

# Short option name for propagate a file option.
PROP_FILE_OPT_SHORT = "-d"

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

# Test IP address.
TEST_IP = "192.168.1.1"

# Test IP address which should fail.
TEST_IP_FAIL = "10.255.255.254"

# A list of IPs for testing subnet scanning.
TEST_IP_LIST = ['127.0.0.1', '127.0.0.0',  '127.0.0.2', '127.0.0.3',
                '127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7',
                '127.0.0.8', '127.0.0.9', '127.0.0.10', '127.0.0.11',
                '127.0.0.12', '127.0.0.13', '127.0.0.14', '127.0.0.15',
                '127.0.0.16', '127.0.0.17', '127.0.0.18', '127.0.0.19',
                '127.0.0.20', '127.0.0.21', '127.0.0.22', '127.0.0.23',
                '127.0.0.24', '127.0.0.25', '127.0.0.26', '127.0.0.27',
                '127.0.0.28', '127.0.0.29', '127.0.0.30', '127.0.0.31',
                '127.0.0.32', '127.0.0.33', '127.0.0.34', '127.0.0.35',
                '127.0.0.36', '127.0.0.37', '127.0.0.38', '127.0.0.39',
                '127.0.0.40', '127.0.0.41', '127.0.0.42', '127.0.0.43',
                '127.0.0.44', '127.0.0.45', '127.0.0.46', '127.0.0.47',
                '127.0.0.48', '127.0.0.49', '127.0.0.50', '127.0.0.51',
                '127.0.0.52', '127.0.0.53', '127.0.0.54', '127.0.0.55',
                '127.0.0.56', '127.0.0.57', '127.0.0.58', '127.0.0.59',
                '127.0.0.60', '127.0.0.61', '127.0.0.62', '127.0.0.63',
                '127.0.0.64', '127.0.0.65', '127.0.0.66', '127.0.0.67',
                '127.0.0.68', '127.0.0.69', '127.0.0.70', '127.0.0.71',
                '127.0.0.72', '127.0.0.73', '127.0.0.74', '127.0.0.75',
                '127.0.0.76', '127.0.0.77', '127.0.0.78', '127.0.0.79',
                '127.0.0.80', '127.0.0.81', '127.0.0.82', '127.0.0.83',
                '127.0.0.84', '127.0.0.85', '127.0.0.86', '127.0.0.87',
                '127.0.0.88', '127.0.0.89', '127.0.0.90', '127.0.0.91',
                '127.0.0.92', '127.0.0.93', '127.0.0.94', '127.0.0.95',
                '127.0.0.96', '127.0.0.97', '127.0.0.98', '127.0.0.99',
                '127.0.0.100', '127.0.0.101', '127.0.0.102', '127.0.0.103',
                '127.0.0.104', '127.0.0.105', '127.0.0.106', '127.0.0.107',
                '127.0.0.108', '127.0.0.109', '127.0.0.110', '127.0.0.111',
                '127.0.0.112', '127.0.0.113', '127.0.0.114', '127.0.0.115',
                '127.0.0.116', '127.0.0.117', '127.0.0.118', '127.0.0.119',
                '127.0.0.120', '127.0.0.121', '127.0.0.122', '127.0.0.123',
                '127.0.0.124', '127.0.0.125', '127.0.0.126', '127.0.0.127',
                '127.0.0.128', '127.0.0.129', '127.0.0.130', '127.0.0.131',
                '127.0.0.132', '127.0.0.133', '127.0.0.134', '127.0.0.135',
                '127.0.0.136', '127.0.0.137', '127.0.0.138', '127.0.0.139',
                '127.0.0.140', '127.0.0.141', '127.0.0.142', '127.0.0.143',
                '127.0.0.144', '127.0.0.145', '127.0.0.146', '127.0.0.147',
                '127.0.0.148', '127.0.0.149', '127.0.0.150', '127.0.0.151',
                '127.0.0.152', '127.0.0.153', '127.0.0.154', '127.0.0.155',
                '127.0.0.156', '127.0.0.157', '127.0.0.158', '127.0.0.159',
                '127.0.0.160', '127.0.0.161', '127.0.0.162', '127.0.0.163',
                '127.0.0.164', '127.0.0.165', '127.0.0.166', '127.0.0.167',
                '127.0.0.168', '127.0.0.169', '127.0.0.170', '127.0.0.171',
                '127.0.0.172', '127.0.0.173', '127.0.0.174', '127.0.0.175',
                '127.0.0.176', '127.0.0.177', '127.0.0.178', '127.0.0.179',
                '127.0.0.180', '127.0.0.181', '127.0.0.182', '127.0.0.183',
                '127.0.0.184', '127.0.0.185', '127.0.0.186', '127.0.0.187',
                '127.0.0.188', '127.0.0.189', '127.0.0.190', '127.0.0.191',
                '127.0.0.192', '127.0.0.193', '127.0.0.194', '127.0.0.195',
                '127.0.0.196', '127.0.0.197', '127.0.0.198', '127.0.0.199',
                '127.0.0.200', '127.0.0.201', '127.0.0.202', '127.0.0.203',
                '127.0.0.204', '127.0.0.205', '127.0.0.206', '127.0.0.207',
                '127.0.0.208', '127.0.0.209', '127.0.0.210', '127.0.0.211',
                '127.0.0.212', '127.0.0.213', '127.0.0.214', '127.0.0.215',
                '127.0.0.216', '127.0.0.217', '127.0.0.218', '127.0.0.219',
                '127.0.0.220', '127.0.0.221', '127.0.0.222', '127.0.0.223',
                '127.0.0.224', '127.0.0.225', '127.0.0.226', '127.0.0.227',
                '127.0.0.228', '127.0.0.229', '127.0.0.230', '127.0.0.231',
                '127.0.0.232', '127.0.0.233', '127.0.0.234', '127.0.0.235',
                '127.0.0.236', '127.0.0.237', '127.0.0.238', '127.0.0.239',
                '127.0.0.240', '127.0.0.241', '127.0.0.242', '127.0.0.243',
                '127.0.0.244', '127.0.0.245', '127.0.0.246', '127.0.0.247',
                '127.0.0.248', '127.0.0.249', '127.0.0.250', '127.0.0.251',
                '127.0.0.252', '127.0.0.253', '127.0.0.254', '127.0.0.255']

# The string used for the touch command
TOUCH_COMMAND = "touch"

# Letting the user know a file couldn't be transferred over SSH default port.
TRANSFER_FAILURE_SSH = "File couldn't be transferred over port 22 / SSH"

# Letting the user know a file could be transferred over port 22 / SSH default
# ports.
TRANSFER_SUCCESS_SSH = "File transferred over port 22 / SSH"

# Unsuccessful statement to be used with services and actions.
UNSUCCESSFUL = "Unsuccessful"

# Help text for the username option.
USERNAME_HELP = "A Username on which we wish to run network propagation " \
                "actions against"

USERNAME_IN_PWS = "using the specified username with a password in the " \
                  "passwords file."

# Short option name for the username option.
USERNAME_OPT_SHORT = "-u"

# Option name for the username option.
USERNAME_OPT_LONG = "--username"

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
        0: [IP_FILE_OPT_SHORT, IP_LIST_SHORT, PORT_OPT_SHORT,
            ALL_PORTS, USERNAME_OPT_SHORT, ADMIN, PW_FILE_OPT_SHORT,
            PWDS_LIST_SHORT],
        # This just runs the scripts against one port / service
        1: [IP_FILE_OPT_SHORT, IP_LIST_SHORT, PORT_OPT_SHORT,
            SSH_PORT, USERNAME_OPT_SHORT, ROOT, PW_FILE_OPT_SHORT,
            PWDS_LIST_SHORT],
        # This propagates a specific file over SSH
        2: [IP_FILE_OPT_SHORT, IP_LIST_SHORT, PORT_OPT_SHORT,
            SSH_PORT, USERNAME_OPT_SHORT, ROOT, PW_FILE_OPT_SHORT,
            PWDS_LIST_SHORT, PROP_FILE_OPT_SHORT, FILE],
        # This is running the automated propagation feature over SSH.
        3: [LAN_OPT_SHORT, PORT_OPT_SHORT, SSH_PORT,
            USERNAME_OPT_SHORT, ROOT, PW_FILE_OPT_SHORT, PWDS_LIST_SHORT,
            PROP_OPT_SHORT],

        # This fails to run the script against all services and four ports
        # because the passwords file filename is invalid.
        4: [IP_FILE_OPT_SHORT, IP_LIST_SHORT, PORT_OPT_SHORT,
            ALL_PORTS, USERNAME_OPT_SHORT, ADMIN, PW_FILE_OPT_SHORT,
            FORCE_FAIL],
        # This fails to run the scripts against one port / service because the
        # OP list filename is invalid.
        5: [IP_FILE_OPT_SHORT, FORCE_FAIL, PORT_OPT_SHORT,
            SSH_PORT, USERNAME_OPT_SHORT, ROOT, PW_FILE_OPT_SHORT,
            PWDS_LIST_SHORT],
        # This fails the propagation of a specific file over SSH because
        # parameter misuse.
        6: [IP_FILE_OPT_SHORT, IP_LIST_SHORT, PWDS_LIST_SHORT,
            SSH_PORT, USERNAME_OPT_SHORT, ROOT, PW_FILE_OPT_SHORT,
            PWDS_LIST_SHORT, PROP_FILE_OPT_SHORT, FILE],
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
    return PARAMETERS + NEWLINE_TAB + IP_FILE_OPT_SHORT + SPACE + \
        ARROW + SPACE + FILENAME_LIST_IP_ADDRESSES + NEWLINE_TAB + \
        PORT_OPT_SHORT + SPACE + ARROW + SPACE + PORTS_TO_SCAN + \
        NEWLINE_TAB + USERNAME_OPT_SHORT + SPACE + ARROW + SPACE + \
        A_USERNAME + NEWLINE_TAB + PW_FILE_OPT_SHORT + SPACE + ARROW + \
        SPACE + FILENAME_PWS_FILE + NEWLINE_TAB + \
        LAN_OPT_SHORT + SPACE + ARROW + SPACE + \
        LOCAL_SCAN_STRING_HELP + NEWLINE_TAB + PROP_OPT_SHORT + SPACE + \
        ARROW + SPACE + HELP_STRING_PROPAGATION + NEWLINE + EXAMPLE_USAGE + \
        NEWLINE_TAB + DEMO_SCRIPT_PATH + SPACE + \
        IP_FILE_OPT_SHORT + SPACE + IP_LIST + SPACE + \
        PORT_OPT_SHORT + SPACE + ALL_PORTS + SPACE + USERNAME_OPT_SHORT + \
        SPACE + ADMIN + SPACE + PW_FILE_OPT_SHORT + SPACE + PWDS_LIST + \
        NEWLINE_NEWLINE_TAB + DEMO_SCRIPT_PATH + \
        IP_FILE_OPT_SHORT + SPACE + IP_LIST + SPACE + \
        PORT_OPT_SHORT + SPACE + SSH_PORT + SPACE + USERNAME_OPT_SHORT + \
        SPACE + ROOT + SPACE + PW_FILE_OPT_SHORT + SPACE + PWDS_LIST


def run_script_command():
    """
    This function will run the propagation script on another target machine
    over any service
    :return: The command itself
    """
    return DEMO_SCRIPT_PATH + SPACE + LAN_OPT_SHORT + SPACE + \
        PORT_OPT_SHORT + SPACE + SSH_PORT + SPACE + USERNAME_OPT_SHORT + \
        SPACE + ROOT + SPACE + PW_FILE_OPT_SHORT + PWDS_LIST + SPACE + \
        PROP_OPT_SHORT


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
