[Wiki](../index.md) / 
# General Usage
A manual of sorts for AutoCompliance. Note that the only functionality that 
exists at the moment is propagation across specific ports and services.

## Running the Propagation Script
The main.py script will automate the process of discovering weak usernames and 
passwords being used for services running on a host. The script will read a 
file containing a list of IP addresses. For each IP address in the list the 
script will scan the ports on that host, and attempt a login for detected 
services.

The script will take in the following parameters:

| Parameter | Purpose                                               |
|-----------|-------------------------------------------------------|
| -t        | Filename for a file containing a list of IP addresses |
| -p        | Ports to scan on the target host                      |
| -u        | A username for login through services                 |
| -f        | Filename for a file containing a list of passwords    |
| -d        | Specify a specific file for propagation               |
| -L        | Perform scan on local networks                        |
| -P        | Propagate the script itself and password file         |

Example usage would look like this:
```
# Running the propagation script across numerous services (SSH, Telnet, Web)
./main.py -t src/test_files/ip_list.txt -p 22,23,25,80 -u admin -f src/test_files/passwords_list.txt

# Running the propagation script just across SSH
./main.py -t src/test_files/ip_list.txt -p 22 -u root -f src/test_files/passwords_list.txt

# Running the propagation script just across SSH and spreading a specific file.
./main.py -t src/test_files/ip_list.txt -p 22 -u root -f src/test_files/passwords_list.txt -d src/test_files/file.txt

# Running the propagation script across SSH and Telnet but acquiring IPs through a local scan and then subsequently self propagating.
./main.py -L -p 22,23 -u root -f src/test_files/passwords_list.txt -P
```