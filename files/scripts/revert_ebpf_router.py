#!/usr/bin/env python3
import os
import subprocess
import sys
import json
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

def delete(rule):
    os.system('yes | /usr/sbin/ufw delete ' + str(rule) + ' > /dev/null 2>&1')

def remove_ufw_rule(rule):
    process = subprocess.Popen(['ufw', 'status',  'numbered'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    count = 1
    for line in data:
        if((line.find(rule) >= 0) & (line.find('ALLOW IN') >= 0)):
            print("removing:", line)
            delete(count)
        if(line.startswith('[')):
            count = count + 1

def iterate_rules(intf):
  rules = ['Anywhere on ' + intf, 'Anywhere (v6) on ' + intf]
  for rule in rules:
      remove_ufw_rule(rule)

if(os.path.exists('/opt/openziti/etc/ebpf_config.json')):
    with open('/opt/openziti/etc/ebpf_config.json','r') as jfile:
        try:
            config = json.loads(jfile.read())
            if(config):
                if("InternalInterfaces" in config.keys()):
                    i_interfaces = config["InternalInterfaces"]
                    if len(i_interfaces):
                        for interface in i_interfaces:
                            if("Name" in interface.keys()):
                                if(interface["Name"] != "lo"):
                                    print("Attempting to restore ufw state: ",interface["Name"])
                                    iterate_rules(interface["Name"])
                            else:
                                print('Mandatory key \"Name\" missing skipping internal interface entry!')
                else:
                    print("No internal interfaces listed in /opt/openziti/etc/ebpf_config.json skipping internal interface ufw reversion interface!")
                if("ExternalInterfaces" in config.keys()):
                    e_interfaces = config["ExternalInterfaces"]
                    if len(e_interfaces):
                        for interface in e_interfaces:
                            if("Name" in interface.keys()):
                                if(interface["Name"] != "lo"):
                                    print("Attempting to restore ufw state: ",interface["Name"])
                                    iterate_rules(interface["Name"])
                            else:
                                print('Mandatory key \"Name\" missing skipping external interface ufw reversion!')
        except Exception as e:
            print("Malformed or missing json object in /opt/openziti/etc/ebpf_config.json can't revert ufw!")

service = False
if(os.path.exists('/etc/systemd/system/ziti-router.service')):
    unconfigured = os.system("grep -r 'ExecStartPre\=\-\/opt/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
    if(not unconfigured):
        test1 = os.system("sed -i 's/#ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/ExecStartPre\=-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/g' /etc/systemd/system/ziti-router.service")
        test2 = os.system("sed -i 's/#ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/g' /etc/systemd/system/ziti-router.service")
        test3 = os.system("sed -i '/ExecStartPre\=\-\/opt\/openziti\/bin\/start_ebpf_router.py/d' /etc/systemd/system/ziti-router.service")
        if((not test1) & (not test2) & (not test3)):
            test1 = os.system("systemctl daemon-reload")
            if(not test1):
                service = True
                print("Successfully reverted ziti-router.service!")
        else:
            print("Failed to revert ziti-router.service!")
    else:
        print("ziti-router.service already reverted. Nothing to do!")
else:
    print("Skipping ziti-router.service reversal. File does not exist!")

if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
    unconfigured = os.system("grep -r '\ \ \ \ \ \ mode: tproxy:/opt/openziti/bin/zfw' /opt/openziti/ziti-router/config.yml")
    if(not unconfigured):
        test1 = os.system("sed -i 's/#mode: tproxy/mode: tproxy/g' /opt/openziti/ziti-router/config.yml")
        test2 = os.system("sed -i '/\ \ \ \ \ \ mode: tproxy:\/opt\/openziti\/bin\/zfw/d' /opt/openziti/ziti-router/config.yml")
        if(test1 | test2):
            print("Unable to revert ziti-router config.yml to use iptables!")
        elif service:
            os.system("/opt/openziti/bin/zfw -Q")
            if(os.path.exists("/opt/openziti/etc/ebpf_config.json")):
                os.remove("/opt/openziti/etc/ebpf_config.json")
            if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
                os.remove("/opt/openziti/bin/user/user_rules.sh")
            print("config.yml successfully reverted. restarting ziti-router.service")
            os.system('systemctl restart ziti-router.service')
            if(not os.system('systemctl is-active --quiet ziti-router.service')):
                print("ziti-router.service successfully restarted")
                if(os.path.exists('/opt/netfoundry/ziti/ziti-router/config.yml')):
                    print("Detected Netfoundry install/registration!")
                    if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
                        print("Removing symlink from /opt/openziti/ziti-router to /opt/netfoundry/ziti/ziti-router")
                        os.unlink('/opt/openziti/ziti-router')
                    else:
                        print("No symlink found nothing to do!")
            else:
                print('ziti-router.service unable to start check router logs')
    else:
        print("ziti-router config already reverted to use iptables!")
else:
    print('ziti-router not installed, skipping ebpf router reversion!')
