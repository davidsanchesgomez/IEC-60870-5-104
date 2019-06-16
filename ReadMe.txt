Author: David Sanches Gómez.

In this Project, an IDS(\textit{Intrusion Detection System}) system has been developed. 
It is capable of analyze the packets transported by the SCADA network, through TCP/IP,
allowing the reception of warnings facing possible anomalies detected on the network.

It is necessary to install Libpcap library:
  apt-get install libpcap0.8-dev
  
For compiling just use:
  gcc -Wall -o iec104_withHash_Final_IP_V3 iec104_withHash_Final_IP_V3.c -lbpcap
  
For the execution you need a file with a pcap extension and IEC 60870-5-104 traffic
To execute: 
  ./iec104_withHash_Final_IP_V3 -f file.pcap
