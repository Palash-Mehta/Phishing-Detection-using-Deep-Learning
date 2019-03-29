# -*- coding: utf-8 -*-
"""
Created on Sun Mar  3 11:22:10 2019

@author: GAJERA_KISHAN
"""

import dns.resolver
import dns
import imgkit
import cv2
from tldextract import extract
import socket

def pharming(url):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['208.67.222.222','208.67.220.220','8.8.8.8','8.8.8.9','156.154.70.1','156.154.71.1']
    subDomain, domain, suffix = extract(url)
    try:
        answer = my_resolver.query(domain+'.'+ suffix)
        addr2 = socket.gethostbyname(domain+'.'+ suffix)#It gives the ip from your DNS
        add1 = []
        for rdata in answer:
           add1.append(str(rdata))    
        if addr2 not in add1:
            config = imgkit.config(wkhtmltoimage="/usr/local/bin/wkhtmltoimage")
            imgkit.from_url('http://'+add1[0], 'out1.jpg',config=config)
            imgkit.from_url('http://'+addr2, 'out2.jpg',config=config)
            original = cv2.imread("out1.jpg")
            duplicate = cv2.imread("out2.jpg")
            # 1) Check if 2 images are equals
            if original.shape == duplicate.shape:
                #print("The images have same size and channels")
                difference = cv2.subtract(original, duplicate)
                b, g, r = cv2.split(difference)
                if cv2.countNonZero(b) == 0 and cv2.countNonZero(g) == 0 and cv2.countNonZero(r) == 0:
                    #print("The images are completely Equal")
                    return 1#Legi
                    #print(1)
            else:
                #print(-1)
                return -1#Attack 
        else:
            #print(1)
            return 1#legi
        #np.array_equal(original,duplicate)
    except Exception:
        #print(0)
        return 0#suspicious
