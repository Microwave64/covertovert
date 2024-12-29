from CovertChannelBase import CovertChannelBase
from scapy.all import IP, Raw, sniff, TCP, UDP
import time

class MyCovertChannel(CovertChannelBase):

    def __init__(self):
        pass

    def send(self, log_file_name, interval:int, error: int, msg_min_length:int, msg_max_length:int):
        # Firstly we created random messages by using predefined generate random message func and alter it to binary msg
        msg = super().generate_random_message(min_length=msg_min_length, max_length=msg_max_length)
        bin_msg = super().convert_string_message_to_binary(msg)

        # Randomly generated message logged into log file without last '.' char in order to use 'make compare' command.
        super().log_message(msg[:-1], log_file_name)

        """
            Packet is only implemented with IP layer with dest and source address, and sent via provided send function
            As we have discussed in the recitation Ether() is not necessary, so we neglect it to not yield any warning
            This is first message which is used as initial point in time calculations
        """
        a = time.time()
        packet = IP(dst="172.18.0.3", src="172.18.0.2")
        super().send(packet)  # (1*) --> represents first packet

        """
            In order to covert secret message, each bit is encoded by random delay in certain interval.
            Additionally, the error parameter is required, due to propogation delay fluctuating the recieving time.
            The error is used to cancel the effect of unwanted time fluctuations due to propogation delay
            In our calculation we initially assumed that: interval = 150 ms, error = 70
        """
        for bit in bin_msg:
            if bit == '0':
                # Message intentionaly delayed in slept interval below encodes 0
                super().sleep_random_time_ms(start=0, end=interval-error)
                super().send(packet)
            elif bit == '1':
                # Message intentionaly delayed in slept interval below encodes 1
                super().sleep_random_time_ms(start=interval+error, end=2*interval)
                super().send(packet)
        print("Time elapsed: ", 128/(time.time() - a))


    def receive(self, interval: int, log_file_name: str):
        """
            Some local variables are declared
            Buffer holds incoming bits until decoding a char
            msg stores decrypted message
        """
        buffer = ""
        msg = ""

        # Flag is used for checking the existence and detection of '.' char --> used in stopper func
        flag = False

        """
            This is first sniff, in order to take first msg (1*)
            This msg is sent and recieved seperately since the covert channel uses intervals,
            and this is starting time of the time calculation
        """
        sniff(filter="host 172.18.0.2 and ip", count = 1)
        time_1 = time.time() * 1000  # Convert to milliseconds

        def process_packet(packet):
            nonlocal buffer, msg, time_1, flag
            time_2 = time.time() * 1000  # Convert to milliseconds
            # Elementary interval calculation
            # Error is not explicityly considered in receiver as it was considered it sender func
            inter = time_2 - time_1
            time_1 = time_2

            # Each bit is decoded one by one according to the principle of our time based covert channel
            if inter < interval:
                buffer += '0'
            else:
                buffer += '1'

            # Since each char is represented in ASCII Table, which is represented in 8 bits
            # When 8 bits are stored into buffer, convert value of buffer to char, push to msg, and clean the buffer
            if len(buffer) == 8:
                new_char = self.convert_eight_bits_to_character(buffer)

                # When the char is '.' stop the function, log the final msg. Also stop to accept more packets
                if new_char == '.':
                    self.log_message(msg, log_file_name)
                    flag = True     
                    """     
                        Used to check the dot char, if dot char is detected than flag becomes true.
                        Which means the stopper func will return true as stop filter to sniff.
                    """
                else:
                    msg += new_char
                    buffer = ""      
                    """    
                        Used to append the decoded char to the decoded message so far and cleaning
                        the buffer for the next packets.
                    """

        # This bool function is called in each sniff as stop-filter in order to halt & terminate capturing packets
        def stopper(packet):
            nonlocal flag
            return flag

        """
            This sniff function takes the all packets except the first one and call process_packet function,
            which handles decoding and logging operations. It also provides the flag used by stopper function
        """
        sniff(filter="host 172.18.0.2 and ip and not icmp", prn=process_packet, stop_filter=stopper)