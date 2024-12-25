from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, IP, Raw, sniff, TCP, UDP
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, interval:int, msg_min_length:int, msg_max_length:int):
        msg = super().generate_random_message(min_length=msg_min_length, max_length=msg_max_length)
        bin_msg = super().convert_string_message_to_binary(msg)
        print(msg)
        print(bin_msg)
        super().log_message(msg, log_file_name)
        packet = Ether(dst="02:42:ac:12:00:03",src="02:42:ac:12:00:02")/IP(dst="172.18.0.3", src="172.18.0.2")/UDP(dport=12345, sport=12345)/Raw(load=msg)
        for bit in bin_msg:
            if bit == '0':
                super().sleep_random_time_ms(start=0, end=interval)
                super().send(packet)
            elif bit == '1':
                super().sleep_random_time_ms(start=interval, end=2*interval)
                super().send(packet)
                

        
    def receive(self, interval: int, log_file_name: str):
        buffer = ""
        msg = ""
        time_1 = time.time() * 1000  # Convert to milliseconds

        def process_packet(packet):
            nonlocal buffer, msg, time_1
            time_2 = time.time() * 1000  # Convert to milliseconds
            inter = time_2 - time_1
            time_1 = time_2
            print(f"Interval: {inter}")

            if inter < interval:
                buffer += '0'
            else:
                buffer += '1'

            if len(buffer) == 8:
                new_char = self.convert_eight_bits_to_character(buffer)
                print(f"Decoded char: {new_char}")
                print(f"Buffer: {buffer}")

                if new_char == ".":
                    self.log_message(msg, log_file_name)
                    return True
                else:
                    msg += new_char
                    buffer = ""

            return False  

        sniff(filter="ip and dst host 172.18.0.3", prn=process_packet, stop_filter=process_packet)




        
                
            
        

