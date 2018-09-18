PyEtherIP
=========

This is a python module to capute and read ethernet frames and ip packets from network.

With pyEtherIP you can monitoring the network traffic writing python's scritps. A simple python script, reads each ethernet frames and ip packets and represents it like a python dictionary.

PyEtherIP is a packet's sniffer that configure the network device in promisc mode to read all traffic from a network segment. 

INSTALL
-------

     $ sudo python setup.py install

Example
-------

This example file called readframes.py (see demos) read ethernet frames

     !/usr/bin/env python
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
                noPromisc('enp5s0',s)
                break

     noPromisc(dev,s)

To execute the script, execute the following commands.

    $ chmod +x readframes.py
    $ ./readframe <mydev> 100

Replace mydev with your network device. The number (100) means that 100 frames will be read.

The output must be a sequence of python dictionaries that represents ethernets frames.

     {'proto': 17, 's_port': 443, 'ethaddr_s': '84:AA:9D:6E:84:10', 'ipaddr_d': '10.0.0.87', 'd_port': 50783, 'ipaddr_s': '192.28.6.82', 'ethaddr_d': '74:27:AA:4B:5E:F1', 'eth_proto': '800'}

See demos for more examples.


