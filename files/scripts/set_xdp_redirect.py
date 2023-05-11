#!/usr/bin/env python3
import subprocess
import os

process = subprocess.Popen(['ip', 'add'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = process.communicate()
data = out.decode().splitlines()
interfaceName = None
ip = '100.64.0.1'
iprange = os.environ.get('ZITI_DNS_IP_RANGE')
if(iprange):
    print('Reading ip from ZITI_DNS_IP_RANGE: ' + iprange)
    ip = iprange.split('/')[0]
else:
    print('Using default tun ip: ' + ip)
for line in data:
    if (line.find(ip) != -1):
        interfaceName = line.split(" ")[-1]
if interfaceName:
   os.system('/usr/sbin/ip link set ' + interfaceName + ' xdpgeneric obj /opt/openziti/bin/zfw_xdp_tun_ingress.o sec xdp_redirect')

