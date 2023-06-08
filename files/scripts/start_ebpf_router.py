#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import time

def tc_status(interface, direction):
    process = subprocess.Popen(['tc', 'filter', 'show', 'dev', interface, direction], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    data = out.decode().splitlines()
    if(len(data)):
        return True
    else:
        return False

if(os.path.exists('/etc/systemd/system/ziti-router.service')):
    unconfigured = os.system("grep -r 'ExecStartPre\=\-\/opt/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
    if(unconfigured):
        test1 = os.system("sed -i 's/ExecStartPre\=\-\/usr\/sbin\/iptables \-F NF\-INTERCEPT \-t mangle/#ExecStartPre\=\-\/usr\/sbin\/iptables \-F NF\-INTERCEPT \-t mangle/g' /etc/systemd/system/ziti-router.service")
        test2 = os.system("sed -i 's/ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/#ExecStartPre\=-\/opt\/netfoundry\/ebpf\/objects\/etables \-F \-r/g' /etc/systemd/system/ziti-router.service")
        test3 = os.system("sed -i 's/ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/#ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/g' /etc/systemd/system/ziti-router.service")
        test4 = os.system("sed -i '/#ExecStartPre\=\-\/opt\/netfoundry\/ebpf\/scripts\/tproxy_splicer_startup.sh/a ExecStartPre\=\-\/opt\/openziti\/bin\/start_ebpf_router.py' /etc/systemd/system/ziti-router.service")
        if((not test1) & (not test2) & (not test3) & (not test4)):
            test1 = os.system("systemctl daemon-reload")
            if(not test1):
                print("successfully converted ziti-router.service")
        else:
            print("failed to convert ziti-router.service")
    else:
        print('Already converted ziti-router.service')
else:
    print("Skipping ziti-router.service conversion file does not exist")

if(os.path.exists('/opt/openziti/ziti-router/config.yml')):
    unconfigured = os.system("grep -r '\ \ \ \ \ \ mode: tproxy:/opt/openziti/bin/zfw' /opt/openziti/ziti-router/config.yml")
    if(unconfigured):
        no_binding = os.system("grep -r '\ \ - binding: tunnel' /opt/openziti/ziti-router/config.yml")
        if(no_binding):
            print('router missing \"binding: tunnel\" aborting router config conversion!')
        else:
            test1 = os.system("sed -i 's/mode: tproxy/#mode: tproxy/g' config.yml")
            test2 = os.system("sed -i '/#mode: tproxy/a \ \ \ \ \ \ mode: tproxy:/opt/openziti/bin/zfw' /opt/openziti/ziti-router/config.yml")
            if(test1 | test2):
                print("unable to convert ziti-router config to use ebpf diverter!")
    else:
        print("ziti-router config already converted to use ebpf diverter!")
else:
    print('ziti-router not installed, skipping ebpf router configuration!')

internal_list = []
external_list = []
per_interface_rules = dict()
outbound_passthrough_track = dict()
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
                                print("Attempting to add ebpf ingress to: ",interface["Name"])
                                internal_list.append(interface["Name"])
                                if("OutboundPassThroughTrack") in interface.keys():
                                    if(interface["OutboundPassThroughTrack"]):
                                        outbound_passthrough_track[interface["Name"]] = True;
                                    else:
                                        outbound_passthrough_track[interface["Name"]] = False;
                                else:
                                    outbound_passthrough_track[interface["Name"]] = False;
                                if("PerInterfaceRules") in interface.keys():
                                    if(interface["PerInterfaceRules"]):
                                        per_interface_rules[interface["Name"]] = True;
                                    else:
                                        per_interface_rules[interface["Name"]] = False;
                                else:
                                    per_interface_rules[interface["Name"]] = False;
                            else:
                                print('Mandator key \"Name\" missing skipping internal interface entry!')

                else:
                    print("No internal interfaces listed in /opt/openziti/etc/ebpf_config.json add at least one interface")
                    sys.exit(1)
                if("ExternalInterfaces" in config.keys()):
                    e_interfaces = config["ExternalInterfaces"]
                    if len(e_interfaces):
                        for interface in e_interfaces:
                            if("Name" in interface.keys()):
                                print("Attempting to add ebpf egress to: ",interface["Name"])
                                external_list.append(interface["Name"])
                                if("OutboundPassThroughTrack") in interface.keys():
                                    if(interface["OutboundPassThroughTrack"]):
                                        outbound_passthrough_track[interface["Name"]] = True;
                                    else:
                                        outbound_passthrough_track[interface["Name"]] = False;
                                else:
                                    outbound_passthrough_track[interface["Name"]] = True;
                                if("PerInterfaceRules") in interface.keys():
                                    if(interface["PerInterfaceRules"]):
                                        per_interface_rules[interface["Name"]] = True;
                                    else:
                                        per_interface_rules[interface["Name"]] = False;
                                else:
                                    per_interface_rules[interface["Name"]] = True;
                            else:
                                print('Mandator key \"Name\" missing skipping external interface entry!')
                else:
                    print("No External interfaces listed in /opt/openziti/etc/ebpf_config.json")
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
        print("failed to clear ebpf maps")
    for i in internal_list:
        if(not tc_status(i, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
            time.sleep(1)
            if(test1):
                print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
                continue
            else:
                print("Attached " + ingress_object_file + " to " + i)
                os.system("sudo ufw allow in on " + i + " to any")
            if(per_interface_rules[i]):
                os.system("/opt/openziti/bin/zfw -P " + i)
        if(not tc_status(i, "egress")):
            if(outbound_passthrough_track[i]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + i + " to tc egress with " + egress_object_file)
                    continue
                else:
                    print("Attached " + egress_object_file + " to " + i)
    for e in external_list:
        if(not tc_status(e, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + ingress_object_file + " -z ingress")
            if(test1):
                os.system("/opt/openziti/bin/zfw -Q")
                print("Cant attach " + e + " to tc ingress with " + ingress_object_file)
                continue
            else:
                print("Attached " + ingress_object_file + " to " + e)
                os.system("sudo ufw allow in on " +e + " to any")
            time.sleep(1)
            if(per_interface_rules[e]):
                os.system("/opt/openziti/bin/zfw -P " + e)
        if(not tc_status(e, "egress")):
            if(outbound_passthrough_track[e]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + e + " to tc egress with " + egress_object_file)
                    os.system("/opt/openziti/bin/zfw -Q")
                    continue
                else:
                    print("Attached " + egress_object_file + " to " + e)
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules")
        os.system("/opt/openziti/bin/user/user_rules.sh")
else:
    print("ebpf already running!");
    os.system("/usr/sbin/zfw -F")
    print("Flushed Table")
    for i in internal_list:
        if(not tc_status(i, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + ingress_object_file + " -z ingress")
            time.sleep(1)
            if(test1):
                print("Cant attach " + i + " to tc ingress with " + ingress_object_file)
            else:
                print("Attached " + ingress_object_file + " to " + i)
                os.system("sudo ufw allow in on " + i + " to any")
            if(per_interface_rules[i]):
                os.system("/opt/openziti/bin/zfw -P " + i)
        if(not tc_status(i, "egress")):
            if(outbound_passthrough_track[i]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + i + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + i + " to tc egress with " + egress_object_file)
                else:
                    print("Attached " + egress_object_file + " to " + i)
    for e in external_list:
        if(not tc_status(e, "ingress")):
            test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + ingress_object_file + " -z ingress")
            if(test1):
                print("Cant attach " + e + " to tc ingress with " + ingress_object_file)
            else:
                print("Attached " + ingress_object_file + " to " + e)
                os.system("sudo ufw allow in on " +e + " to any")
            time.sleep(1)
            if(per_interface_rules[e]):
                os.system("/opt/openziti/bin/zfw -P " + e)
        if(not tc_status(e, "egress")):
            if(outbound_passthrough_track[e]):
                test1 = os.system("/opt/openziti/bin/zfw -X " + e + " -O " + egress_object_file + " -z egress")
                if(test1):
                    print("Cant attach " + e + " to tc egress with " + egress_object_file)
                else:
                    print("Attached " + egress_object_file + " to " + e)
    if(os.path.exists("/opt/openziti/bin/user/user_rules.sh")):
        print("Adding user defined rules")
        os.system("/opt/openziti/bin/user/user_rules.sh")
    sys.exit(0)
