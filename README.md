# Arp-Spoofing-Tool

This is a tool designed for Man-in-the-middle(MitM) and Denial-of-service(DoS) attacks. 

## Prerequisites 
* scapy 2.4.0 or higher
* python 3.6 or higher

## Installation
Clone or download the code in master branch for Mac OS and  linux branch for Linux OS. 

## How to use?
After getting the correct version of the code, open a terminal. Go to the directory of the program and run the following command:
` python3 main.py `

If you have another version of python3 as default, you may need to specify it: ` python3.6 main.py `

Then, you will encounter with a menu asking you to choose an option.

![Menu](/menu.png)

In order to attack an IP address, first
you have to list the online hosts. Therefore, you have to choose 1 at least once before any attack.
Selecting option 2 starts a Man-in-the-middle attack to the victim's IP address. (You will be asked to enter the victim IP). Now you can listen
the network of the victim and get the packets till you give a keyboard interrupt. After the attack ends, a pcap file will be created 
for the captured packets.

*Note that* in mitm attack, victim has a proper internet connection. 

Denial-of-server attack runs similarly. Again, you need to give the victim IP. After Dos attack starts, victim will loose his/her
connection. The requested packets will come to you. In the end, those packets are stored in a pcap file. 

Stopping an attack will restore the network.


## Contributers
* Uğurcan Arıkan
* Yaşar Alim Türkmen
