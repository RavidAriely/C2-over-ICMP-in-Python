
# Command and Control (C2) in Python

An implementation of a Command and Control (C2) server and agent in Python.

Note: This tool is intended for educational purposes only.

## Prerequisites
Ubuntu virtual machine with sudo access (for the agent).

## Server

Receives beacons from agents, sends commands, manages file transfers, and collects results.

1. Clone this repository to your local PC.
2. Install scapy: 
   ```bash
   sudo apt-get install python3-scapy
   ```
3. Edit the `config.txt` file with the following parameters:
     * Interface: use ```ip a``` 
     * Path: choose a path for the collected results from the agent.
4. Run the program:
   ```bash
   sudo python3 server.py
   ```
5. Enter commands in the following foramt: `run <command>` or `send </path/to/file>`


## Agent

Simulates compromised agent communicating with the C2 server using ICMP packets.<br>
It executes commands from the server, supports file transfer, and sends results back.

1. Clone this repository to the VM. 
2. Modify the server's IP address in the init method to match your server's actual IP address.
3. Run the program:
   ```bash
   sudo python3 agent.py
   ```
## Demo

[![c2 demo](https://res.cloudinary.com/marcomontalbano/image/upload/v1692620795/video_to_markdown/images/youtube--pY6tInde0ak-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://www.youtube.com/watch?v=pY6tInde0ak "c2 demo")


## Behavioral Guidelines

The C2 server works with only one agent currently.


# C2-over-ICMP-in-Python
