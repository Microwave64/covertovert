# IP Interarrival Time Covert Channel
Fatih Emre Güneş - 2580603
Ozan Yanık - 2581163

## General Information

Covert channels utilize steganographic techniques to facilitate communication. Unlike cryptography, where messages are transformed and sent directly, covert channels conceal messages within other physical layers, such as timing or packet header modifications. This project focuses on a covert timing channel that leverages the interarrival times of incoming IP packets. In this method, the sender encodes information in the time gaps between consecutive packets. For instance, a short interval might signify a '0', while a longer interval could denote a '1'. The receiver then decodes the hidden data by measuring these interarrival times.

## Constraints

For the covert channel to work properly, the minimum value for the *interval* is 120 and the minimum value for *error* is 60 in this case. They can be increased but *error* should be adjusted proportional to *interval*. *error* should not be small than the limit so that the channel is not affected by the propagation and processing delay.

## Detailed Operational Overview

### Sender 

First of all, the sender starts by creating a random message using the **generate_random_message** with a length in the range provided by the parameters of the send function. Then this message is converted to a binary string with **convert_string_message_to_binary** function. After that, it is logged to the file of which name is provided in the *log_file_name* parameter of the **send** function by the **log_message** function. Next, the sender sends an IP packet to the receiver to synchronization.
After this moment, the sender sends an IP packet for each bit in the binary string message. Between each IP packet, the sender waits for a certain amount of time which is determined by the *interval* and *error* parameters of the send function. This time is randomly chosen between 0 ms and (*interval*-*error*) ms if the current bit of the binary string is '0'. If the current bit is '1', then the waiting time is again chosen randomly between (*interval*+*error*) ms and (2**interval*) ms. 
We are using the *error* parameter here, since each packet sent has a propagation delay and this sometimes affect the communication between the sender and the receiver. The aim of the usage of the *error* parameter is to guarantee the receiver to understand the message correctly. While increasing the *error* variable also increases the reliability of the channel, it decreases the variety of the inter-arrival times of the packets; so it decreases the undetectibiity.

### Receiver

Firstly, the receiver allocates spaces for storing decoded characters, storing the decoded bits and it sets a **flag** as False. The receiver uses the sniff function of the **scapy** library. We use 3 arguments for sniff function:\
**1)** filter: For filtering the IP packets coming from the sender's IP address. The receiver does not use any other packets than IP packets and also the packets coming from other hosts are also discarded.\
**2)** prn: Processing each packet. This argument takes a function which is used for processing each packet after their arrival. We used a function called **process_packet** which is going to be explained next.\
**3)** stop_filter: To decide whether the sniff function should stop. We use a function called **stopper** which just returns the **flag** variable. If the flag is True, the sniff function stops so does the receiving operation.\
The receiver measures the initial time and stores it in the **time_1** variable to use it to compute the inter-arrival times.
After each packet arrives to the receiver, they are processed by the **process_packet** function. In this function the following operations are executed:\
First of all, the current time is measured and stored in the **time_2** variable. This varible marks the time of the arrival of the new packet. Then to find the inter-arrival time, **time_1** is subtracted from **time_2**. After that, **time_1** is set to **time_2** as a preparation for the new incoming packet. Then, if the inter-arrival time is less than the *interval* argument, we add a '0' bit to the buffer. Otherwise, we add a '1' bit to the buffer. We do this since the sender sends the packets with delay determined by the *interval*. We do the previous operations continously until the buffer length becomes 8. The limit is 8 because the ASCII values range from 0 to 255 and these numbers are represented by 8 bits. So when we have 8 bits, this means we have a character. It is decoded by **convert_eight_bits_to_character** function. The ends of the messages are marked with '.' (dot) character, so if the new decoded character is '.', this means the receiver has successfully received the full message and after that the message is logged to the file of which name is provided in the *log_file_name* parameter of the **receive** function by the **log_message** function. Also, the **flag** is set to True in order to stop the sniff function. If the decoded character is not '.', then it is appended to the **msg** variable which stores the message received so far. Then the buffer is emptied receiving the next packet and the operations continue to be executed.

## Channel Capacity

We have tested the capacity of the covert channel multiple times with strings having 16 characters. The maximum channel capacity we got is 7.35466606171295 bits/second and the mininum is 6.108697769781235 bits/second.