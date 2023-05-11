#!/usr/bin/env python3
import os
import sys
import json
import subprocess


interface_list = [];
if(os.path.exists('/opt/openziti/etc/ebpf_config.json')):
    with open('/opt/openziti/etc/ebpf_config.json','r') as jfile:
        try:
            j_object = json.loads(jfile.read())
            if(j_object):
                config = j_object["Config"]
                interfaces = config["Interfaces"]
                if len(interfaces):
                    for interface in interfaces:
                        print("Attempting to add ebpf to: ",interface["Name"])
                        interface_list.append(interface["Name"])
                else:
                    print("No interfaces listed in /opt/openziti/etc/ebpf_config.json add at least one interface")
        except Exception as e:
            print("Malformed or missing json object in /opt/openziti/etc/ebpf_config.json")
            sys.exit(1)
else:
    print("Missing /opt/openziti/etc/ebpf_config.json can't set ebpf interface config")
    sys.exit(1)

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

if os.system("/opt/openziti/bin/map_update -L -E"):
    test1 = os.system("/opt/openziti/bin/map_update -Q")
    if test1:
        sys.exit(1)
    for i in interface_list:
        test2 = os.system("/opt/openziti/bin/map_update -X " + i + " -O /opt/openziti/bin/tproxy_splicer.o -z ingress")
        test3 = os.system("/opt/openziti/bin//map_update -T " + i)
        #os.system("/usr/sbin/map_update -v eth0")
        if(test2 | test3):
            sys.exit(1)
        else:
            if interfaceName:
                os.system("sudo ufw route allow in on " + i +" out on " + interfaceName)
            else:
                print("can't determin tun if may need to enable forwading maunally if running ufw")
            os.system("sudo ufw allow in on " + i + " to any")
else:
    print("ebpf already running!");
    os.system("/usr/sbin/map_update -F")
    print("Flushed Table")
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules")
        os.system("/opt/openziti/bin/user/user_rules.sh")
    for i in interface_list:
        test2 = os.system("/opt/openziti/bin/map_update -X " + i + " -O /opt/openziti/bin/tproxy_splicer.o -z ingress")
        test3 = os.system("/opt/openziti/bin//map_update -T " + i)
        #os.system("/usr/sbin/map_update -v eth0")
        if(test2 | test3):
            sys.exit(1)
        else:
            if interfaceName:
                os.system("sudo ufw route allow in on " + i +" out on " + interfaceName)
            else:
                print("can't determin tun if may need to enable forwading maunally if running ufw")
            os.system("sudo ufw allow in on " + i + " to any")
    sys.exit(0)
