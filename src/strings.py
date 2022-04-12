#!/usr/bin/python3

# A string that just states "Adding".
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

# The main script.
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

# Let the user know that we're checking to see if the IP address is reachable.
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

# "Login to" string, another string building constant.
LOGIN_TO = "login to"

# The typical ID of the loopback interface.
LOOPBACK = "lo"

# The main script.
MAIN_SCRIPT = "./main.py"

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
