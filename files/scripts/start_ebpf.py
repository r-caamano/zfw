#!/usr/bin/env python3
import os
import sys
import json
import subprocess

def tc_status(interface, direction):
    process = subprocess.Popen(['tc', 'filter', 'show', 'dev', interface, direction], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    if(len(data)):
        return True
    else:
        return False

internal_list = []
external_list = []
if(os.path.exists('/opt/openziti/etc/ebpf_config.json')):
    with open('/opt/openziti/etc/ebpf_config.json','r') as jfile:
        try:
            config = json.loads(jfile.read())
            if(config):
                if("InternalInterfaces" in config.keys()): 
                    i_interfaces = config["InternalInterfaces"]
                    if len(i_interfaces):
                        for interface in i_interfaces:
                            print("Attempting to add ebpf to: ",interface["Name"])
                            internal_list.append(interface["Name"])
                else:
                    print("No internal interfaces listed in /opt/openziti/etc/ebpf_config.json add at least one interface")
                    sys.exit(1)
                if("ExternalInterfaces" in config.keys()):
                    e_interfaces = config["ExternalInterfaces"]
                    if len(e_interfaces):
                        for interface in e_interfaces:
                            print("Attempting to add ebpf to: ",interface["Name"])
                            external_list.append(interface["Name"])
                else:
                    print("No External interfaces listed in /opt/openziti/etc/ebpf_config.json no outbound tracking")
        except Exception as e:
            print("Malformed or missing json object in /opt/openziti/etc/ebpf_config.json")
            sys.exit(1)
else:
    print("Missing /opt/openziti/etc/ebpf_config.json can't set ebpf interface config")
    sys.exit(1)

ingress_object_file = '/opt/openziti/bin/zfw_tc_ingress.o'
egress_object_file = '/opt/openziti/bin/zfw_tc_outbound_track.o'
if os.system("/opt/openziti/bin/zfw -L -E"):
    test1 = os.system("/opt/openziti/bin/zfw -Q")
    if test1:
        sys.exit(1)
    for i in internal_list:
        test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
        test2 = os.system("/opt/openziti/bin/zfw -T " + i)
        if(test1 | test2):
            print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
            sys.exit(1)
        else:
            os.system("sudo ufw allow in on " + i + " to any")
    for e in external_list:
        test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
        test2 = os.system("/opt/openziti/bin/zfw -P " + e)
        if(test1 | test2):
            print("Cant attach " + e + " to tc egress with " + egress_object_file) 
            sys.exit(1)
else:
    print("ebpf already running!");
    os.system("/usr/sbin/zfw -F")
    print("Flushed Table")
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules")
        os.system("/opt/openziti/bin/user/user_rules.sh")
    for i in internal_list:
        if(not tc_status(i, "ingress")):
          test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
          test2 = os.system("/opt/openziti/bin/zfw -T " + i)
          if(test1 | test2):
              print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
              sys.exit(1)
          else:
            os.system("sudo ufw allow in on " + i + " to any")
    for e in external_list:
        if(not tc_status(e, "egress")):
          test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
          test2 = os.system("/opt/openziti/bin/zfw -P " + e)
          if(test1 | test2):
              print("Cant attach " + e + " to tc egress with " + egress_object_file)
              sys.exit(1)
    sys.exit(0)
