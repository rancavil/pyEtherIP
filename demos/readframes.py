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
