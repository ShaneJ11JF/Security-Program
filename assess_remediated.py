#---Importing neccessary packages to run program---#

import socket
import os
import sys
import subprocess
import nmap
import scapy
from scapy.all import *

# Function interface is printed to user to give them a list of choices
def interface():
    print("[1] Port Scan")
    print("[2] Ping an IP")
    print("[3] Packet Sniffing")
    print("[4] Nmap IP Scan")
    print("[5] Install Security Tools")
    print("[7] Shutdown or Restart Device")
    print("[8] Exit Program")

interface()

def port_scan(): # Function that uses sockets for port scanning
    t_host = str(input("Enter host to be scanned...")) # Asks user for host name and stores in variable
    t_ip = socket.gethostbyname(t_host) # Resolves t_host to ipv4 Address, gets current IP address

    print(t_ip) # Print the IP to the user
        
    while True: # While loop to run through user prompt
        t_port = int(input("Enter the port: ")) # Prompts user to enter the port

        try:
            sock = socket.socket() # Create a socket
            res = sock.connect((t_ip, t_port)) # Connect to remote socket, receives host and port
            break
            print("Port {}: Open" .format(t_port)) # Port is Open
            sock.close() # End the socket connection
        except:
            print("Port {}: Closed" .format(t_port)) # Port is Closed
            break
    print("Port Scanning Complete")

def ping_ip():
    # Prompt user for IP they wish to ping, store in variable
    ip = input("Please enter the IP you wish to ping...")

    # Pings IP provided by user using os.system function
    os.system("ping " + ip)
    print("Ping Complete.") # Print completion message to user

def packet_sniffer(): # Packet Sniffer Function
    print("Guide: To sniff a number of packets, enter the following command into scapy: sniff(count=x) where x = the number of packets")
    print("When you are finished with the program, please type exit()")

    scapy_enable = input("Would you like to enable Scapy?(y/n)")

    if scapy_enable == "y": # If user enters 'y'
        os.system("scapy")  # Open scapy environment
    else:                   # Otherwise
            exit()              # Exit this option

def nmap_scan(): # Nmap Scan function
    nmScan = nmap.PortScanner() # Initialise PortScanner from nmap library

    ip_scan = str(input("Enter the IP you would like to scan...")) # Prompt user for IP address
    port_scan = str(input("Enter the port(s) you would like to scan...")) # Prompt user for port or port range they wish to scan

    nmScan.scan(ip_scan, port_scan) # Set nmScan to scan the variables the user has given

    for host in nmScan.all_hosts(): 
        print('Host: %s (%s)' % (host, nmScan[host].hostname())) # Prints the host the user has entered
        print('State : %s' % nmScan[host].state())               # Prints the status of the host (up/down)
        for proto in nmScan[host].all_protocols():               # For loop that checks protocols in selected ports
                print('---------------')                            # Break line for formatting
                print('Protocol : %s' % proto)                      # Print the protocol in use (tcp/udp etc)
                 
                lport = nmScan[host][proto].keys() # Store host and protocol info in this variable
                for port in lport: # For loop through lport
                     print('port %s\tstate : %s' % (port, nmScan[host][proto][port]['state'])) # Print the protocols/ports/status to user

def install_sec_tools(): # Function to install necessary tools via pip as a subprocess
    # Run pip installs as a subprocess to install the packages required for the rest of the program
    subprocess.call([sys.executable, "-m", "pip", "install", 'scapy'])
    subprocess.call([sys.executable, "-m", "pip", "install", 'python-nmap'])


    # Finds the package and outputs its current version
    reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])

    # Creates installed_packages variable and stores currently installed packages in it
    installed_packages = [r.decode().split('==')[0] for r in reqs.split()] 

    # Prints to user the packages that they now have installed
    print(installed_packages)

def shut_or_res(): # Function to restart or shutdown the device
     shut_or_res = input("Do you want to shutdown or restart your device?...(please type shutdown or restart)")

     if shut_or_res == 'shutdown': # If user enters 'shutdown'
        os.system("shutdown /s /t 1") # Shut down device
     elif shut_or_res == 'restart': # Otherwise, if user enters 'restart'
        os.system("shutdown /r /t 1") # Restart device

def exit_program(): # Function that exits the program
    print("EXITING PROGRAM...") 
    sys.exit() # Exits the program


choice = int(input("Pick an option from the menu from 1 - 8...")) # Gather user option and store as variable

while choice != 0: # While the user's choice isn't '0'
    if choice == 1: # Code for first option - Scanning a Port
        port_scan() # Call port scan function
       
        print() # Create a block to separate the output 
        interface() # Call the interface options again
        choice = int(input("Pick an option from the menu from 1 - 8...")) # Prompt user for another choice

    if choice == 2: # Code for 2nd option - Pinging an IP
        ping_ip() # Call ping_ip function
      
        print()
        interface()
        choice = int(input("Pick an option from the menu from 1 - 8..."))  # Prompt user for another choice

    if choice == 3: # Code for 3rd option - Packet Sniffing
        packet_sniffer() # Call packet_sniffer function
       
        print()
        interface()
        choice = int(input("Pick an option from the menu from 1 - 8..."))  # Prompt user for another choice
        

    if choice == 4: # Code for 4th option - Scan an IP via nmap
        nmap_scan() # Call the nmap_scan function
        
        print()
        interface()
        choice = int(input("Pick an option from the menu from 1 - 8..."))  

    if choice == 5: # Code for the 5th option - Install necessary packages
        install_sec_tools() # Call install_sec_tools function
        
        print()
        interface()
        choice = int(input("Pick an option from the menu from 1 - 8..."))  # Prompt user for another choice

    if choice == 7: # Code for the 7th option - Shutdown or Restart the device
        shut_or_res() # Call shut_or_res function
        
        print()
        interface()
        choice = int(input("Pick an option from the menu from 1 - 8..."))  # Prompt user for another choice
    
    if choice == 8: # Code for the 8th option - Exit the Program
        exit_program() # Exit program

# END OF PROGRAM #