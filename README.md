PyEtherIP
=========

This is a python module to capute and read ethernet frames and ip packets from network.

With pyEtherIP you can monitoring the network traffic writing python's scritps. A simple python script, reads each ethernet frames and ip packets and represents it like a python dictionary.

PyEtherIP is a packet's sniffer that configure the network device in promisc mode to read all traffic from a network segment. 

INSTALL
-------

     $ pip install git+https://github.com/rancavil/pyEtherIP.git

or 

     $ git clone https://github.com/rancavil/pyEtherIP.git
     $ sudo python setup.py install

Example
-------

This example file called readframes.py (see demos) read ethernet frames

     #!/usr/bin/env python
     import sys
     from pyEtherIP import *

     if __name__ == '__main__':
         if len(sys.argv) < 3:
             print('Usage : sudo readframes.py <network_interface> <num_frames>')
             sys.exit(1)
         dev = sys.argv[1]
         num = int(sys.argv[2])
         s = promisc(dev)
         count = 0;
         while count < num:
            try:
                frame = readFrame(s);
                if frame != None:
                    print(frame)
                    count = count + 1
            except KeyboardInterrupt:
                    print('Stop')
                    noPromisc(dev,s)
                    break

         noPromisc(dev,s)

To execute the script, execute the following commands.

    $ chmod +x readframes.py
    $ sudo ./readframe <mydev> 100

To run you must be root.

Replace mydev with your network device. The number (100) means that 100 frames will be read.

The output must be a sequence of python dictionaries that represents ethernet frames.

     {'proto': 17, 's_port': 443, 'ethaddr_s': '84:AA:9D:6E:84:10', 'ipaddr_d': '10.0.0.87', 'd_port': 50783, 'ipaddr_s': '192.28.6.82', 'ethaddr_d': '74:27:AA:4B:5E:F1', 'eth_proto': '800'}

The dictionary shows a raw ethernet frame.

For example, proto 17 = UDP, proto 6 = TCP, ethaddr_s and ethaddr_d are the MAC of source (origin) and destination, ipaddr_s and ethaddr_d are the source (origin) and destination ip addresses, and eth_proto is the type of protocol transported in the frame, 800 is 0x0800 IP.

See demos for more examples.


