#!/usr/bin/python3

# Author: @andrewk10

# Importing strings for use of the external strings resources.
import strings


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
    return strings.ADDING + strings.SPACE + str(specific_address) + \
        strings.SPACE + strings.FROM_INTERFACE + strings.SPACE + \
        str(interface) + strings.INTERFACE_SUBNET


def cat_file(filename):
    """
    This function creates a command for concatenating a specific file
    :param filename: The filename of the file we want to touch
    :return "cat " + filename: The completed cat command
    """
    return strings.CAT + strings.SPACE + filename


def checking_ip_reachable(ip):
    """
    This function creates a string that describes the availability of a machine
    on a specific IP address
    :param ip: The specific IP address
    :return "Checking if the following ip address is reachable: " + str(ip):
    The string in question
    """
    return strings.IS_IP_REACHABLE + strings.SPACE + str(ip)


def connection_status(service, ip, port, status):
    """
    This function creates the connection status string dependent
    on the context given by the arguments passed into it.
    """
    return str(status) + strings.SPACE + str(service) + strings.SPACE + \
        strings.LOGIN_TO + strings.SPACE + str(ip) + strings.COLON + \
        str(port) + strings.SPACE + strings.USERNAME_IN_PWS


def fetching_ips_for_interface(interface):
    """
    This function generates the string for fetching the IPs for a specific
    interface
    :param interface: The interface we're fetching IPs on
    :return "Fetching IPs for interface " + str(interface) + "...": The string
    in question
    """
    return strings.FETCHING_INTERFACE_IPS + strings.SPACE + str(interface) + \
        strings.ELLIPSES


def file_present_on_host(ip):
    """
    This function generates the string for a file already present on a host
    :param ip: The host itself
    :return "A file is already present on this host: " + str(ip): The string
    in question
    """
    return strings.FILE_PRESENT_ON_HOST + strings.SPACE + str(ip)


def filename_processing_error(filename):
    """
    A processing error printout for a specific filename.
    :param filename: The filename of the file we're struggling to process
    combination
    :return: The string itself
    """
    return strings.FILENAME_PROCESSING_ERROR + strings.COLON + \
        strings.SPACE + filename


def help_output():
    """
    This is the help output for when the user passes in the help parameter
    :return: The output itself.
    """
    return strings.PARAMETERS + strings.NEWLINE_TAB + \
        strings.IP_FILE_OPT_SHORT + strings.SPACE + \
        strings.ARROW + strings.SPACE + strings.FILENAME_LIST_IP_ADDRESSES + \
        strings.NEWLINE_TAB + strings.PORT_OPT_SHORT + strings.SPACE + \
        strings.ARROW + strings.SPACE + strings.PORTS_TO_SCAN + \
        strings.NEWLINE_TAB + strings.USERNAME_OPT_SHORT + strings.SPACE + \
        strings.ARROW + strings.SPACE + strings.A_USERNAME + \
        strings.NEWLINE_TAB + strings.PW_FILE_OPT_SHORT + strings.SPACE + \
        strings.ARROW + strings.SPACE + strings.FILENAME_PWS_FILE + \
        strings.NEWLINE_TAB + strings.LAN_OPT_SHORT + \
        strings.SPACE + strings.ARROW + strings.SPACE + \
        strings.LOCAL_SCAN_STRING_HELP + strings.NEWLINE_TAB + \
        strings.PROP_OPT_SHORT + strings.SPACE + strings.ARROW + \
        strings.SPACE + strings.HELP_STRING_PROPAGATION + strings.NEWLINE + \
        strings.EXAMPLE_USAGE + strings.NEWLINE_TAB + strings.MAIN_SCRIPT + \
        strings.SPACE + strings.IP_FILE_OPT_SHORT + \
        strings.SPACE + strings.IP_LIST + strings.SPACE + \
        strings.PORT_OPT_SHORT + strings.SPACE + strings.ALL_PORTS + \
        strings.SPACE + strings.USERNAME_OPT_SHORT + strings.SPACE + \
        strings.ADMIN + strings.SPACE + strings.PW_FILE_OPT_SHORT + \
        strings.SPACE + strings.PWDS_LIST + strings.NEWLINE_NEWLINE_TAB + \
        strings.MAIN_SCRIPT + strings.IP_FILE_OPT_SHORT + \
        strings.SPACE + strings.IP_LIST + strings.SPACE + \
        strings.PORT_OPT_SHORT + strings.SPACE + strings.SSH_PORT + \
        strings.SPACE + strings.USERNAME_OPT_SHORT + strings.SPACE + \
        strings.ROOT + strings.SPACE + strings.PW_FILE_OPT_SHORT + \
        strings.SPACE + strings.PWDS_LIST


def ip_list_not_read(filename):
    """
    This function returns the error for an ip list that can't be generated from
    a particular filename
    :param filename: The filename of the file that can't have an ip list
    derived from it
    :return: The string in question
    """
    return strings.CAN_NOT_READ_IP_LIST + strings.SPACE + filename


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
        return str(ip) + strings.SPACE + strings.WAS_REACHABLE + \
            strings.FULL_STOP
    return str(ip) + strings.SPACE + strings.WAS_NOT_REACHABLE + \
        strings.FULL_STOP


def netcat_listener(port, filename):
    """
    This function will create a netcat listener on the device we have a netcat
    link to
    :param port: The port on which the netcat listener will operate
    :param filename: The filename of the file we're moving using the listener
    parameter
    :return: The string in question
    """
    return strings.NETCAT_LISTENER_PORT_COMMAND + strings.SPACE + str(port) + \
        strings.SPACE + strings.GREATER_THAN + strings.SPACE + filename


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
    return strings.NETCAT_WRITER_COMMAND + strings.SPACE + str(ip) + \
        strings.SPACE + str(port) + strings.SPACE + strings.LESS_THAN + \
        strings.SPACE + filename


def run_script_command():
    """
    This function will run the propagation script on another target machine
    over any service
    :return: The command itself
    """
    return strings.MAIN_SCRIPT + strings.SPACE + \
        strings.LAN_OPT_SHORT + strings.SPACE + \
        strings.PORT_OPT_SHORT + strings.SPACE + strings.SSH_PORT + \
        strings.SPACE + strings.USERNAME_OPT_SHORT + strings.SPACE + \
        strings.ROOT + strings.SPACE + strings.PW_FILE_OPT_SHORT + \
        strings.PWDS_LIST + strings.SPACE + strings.PROP_OPT_SHORT


def scp_command_string(port, username, target_ip, filename):
    """
    This function creates and SSH copy string for an OS command
    :param port: Port over which we are running the SSH copy
    :param username: The username for the SSH login
    :param target_ip: The IP address of the machine we are copying too
    :param filename: The name of the file to be copied across by SSH
    :return: The SSH copy command
    """
    return strings.SCP_COMMAND + strings.SPACE + str(port) + strings.SPACE + \
        filename + strings.SPACE + username + strings.AT_SYMBOL + target_ip + \
        strings.HOME_DIR


def touch_file(filename):
    """
    This function creates a command for touching a specific file
    :param filename: The filename of the file we want to touch
    :return: The completed touch command
    """
    return strings.TOUCH_COMMAND + strings.SPACE + filename


def web_login_url(ip, port):
    """
    This function will build the web login url string
    :param ip: The IP of the machine running the web service
    :param port: The port the web service is running on
    :return: The string itself
    """
    return strings.HTTPS_STRING + ip + strings.COLON + port + strings.LOGIN_PHP


def working_username_password(service):
    """
    This function will build a string for a working username and password given
     a specific service
    :param service: Service for which there is a working username and password
    combination
    :return: The string itself
    """
    return strings.WORKING_USERNAME_PASS + strings.SPACE + str(service) + \
        strings.SPACE + strings.WAS_FOUND
