## Introduction
--- 
This firewall applicaion utilizes both tc-ebpf and xdp to provide statefull firewalling
for openziti ziti-edge-tunnel installation and is meant as a replacement for ufw at least for
ingress filtering.  It can be used in conjuction with ufw's masquarade feature on a wan facing interface if
the zfw_outbound_track.o is activated in the egress direction. I can also be used in conjunction with openziti
edge-routers deb package / manual instructions not yet available but comming soon.


## Build
---
[To build zfw from source. Click here!](./BUILD.md)

## Management After Deployment
---

The program is designed to be deployed as systemd services if deployed via .deb package with
an existing ziti-edge-tunnel(v21.0 +) service installation.  

-install
```
dpkg -i zfw_<ver>_<arch>.deb
```

files will be installed in the following directories
   /etc/systemd/system <systemd service files>  
   /usr/sbin <symbolic link to zfw executable>
   /opt/openziti/etc : <config files> 
   /opt/openziti/bin : <binary executables, executable scripts, binary object files>
   /opt/openziti/bin/user: <user configured rules>

configure:
   edit interfaces:
    sudo cp /opt/openziti/etc/ebpf_config.yml.sample /opt/openziti/etc/ebpf_config.yml
    sudo vi /opt/openziti/etc/ebpf_config.yml

    replace eth0 in line with:{"Interfaces":[{"Name":"eth0"}]} 
    Replace with interface you want to enable for ingress firewalling/ openziti interception
    i.e. ens33
    {"InternalInterfaces":[{"Name":"ens33"}]}
    Note if you want to add more than one add to list
    {"InternalInterfaces":[{"Name":"ens33"} {"Name":"ens37"}]}

   add user configured rules:
   sudo cp /opt/openziti/bin/user/user_rules.sh.sample /opt/openziti/bin/user/user_rules.sh
   sudo vi /opt/openziti/bin/user_rules.sh
   
Enable services:
   Assuming ziti-edge-tunnel is running: 
```  
    sudo systemctl enable ziti-fw-init.service
    sudo systemctl enable ziti-wrapper.service 
    sudo systemctl restart ziti-edge-tunnel 
```
service will automatically configure ufw (if enabled) to hand off to ebpf on configured interface(s).  Exception is icmp
which must be maually enabled if its been disabled in ufw.  also to allow icmp to ip of configured interface you would need to
set icmp to enabled in the user_rules.sh i.e. sudo zfw -e ens33 file and restart either the wrapper service or ziti-edge-tunnel 

i.e. from above example ebpf_config zfw sets
sudo ufw allow in on <ens33> to any
Verify running
```
   sudo zfw -L
```
output:
   if running assuming using default address for ziti-edge-tunnel should see output like:

target  	proto	origin              destination             mapping:                				                interface list                 
--------	-----	-----------------	------------------		-------------------------------------------------------	-----------------
TUNMODE    	tcp	    0.0.0.0/0           100.64.0.0/10           dpts=1:65535     	TUNMODE redirect:tun0               []
TUNMODE    	udp	    0.0.0.0/0           100.64.0.0/10           dpts=1:65535     	TUNMODE redirect:tun0               []

verify running on the configured interface i.e.
```
sudo tc filter show dev ens33 ingress
```
expected output:
filter protocol all pref 49152 bpf chain 0 
filter protocol all pref 49152 bpf chain 0 handle 0x1 zfw_tc_ingress.o:[action] direct-action not_in_hw id 240 tag 689a7073bde6f9b0 jited
<there will be no output if not running>

Services configured via the openziti controller for ingress on the running ziti-edge-tunnel identities will auto populate into
the firewalls inbound rule list.

also note xdp is enabled on the tunX interface that ziti-edge tunnel is attached to support functions like bi-directional 
ip transparency which would otherwise not be possible without this fw/wrapper.

you can check this as follows

sudo ip link show dev tunX where X is the tun interface numbrer i.e. default tun0

```
sudo ip link show tun0
```
expected output:
9: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500
    link/none 
    prog/xdp id 249 tag 06c4719358c6de42 jited  <This line will be there if exp forwarder is running>


```
-remove services and files
```
dpkg -i zfw
sudo reboot
```


The firewall can support subtending devices for two interface scenarios i.e.
external and trusted.

    external inet <----> (ens33)[ebpf-router](ens37) <----> trusted clients

    with tproxy-splicer.o applied ingress on ens33 and oubound_track.o applied egress on ens33 the router will
    statefully track outbound udp and tcp connections on ens33 and allow the associated inbound traffic.  While
    running in this mode it does not make sense to add ziti tproxy rules and is meant for running as a traditional fw.
    As be for you can also create passthrough FW rules (set -t --tproxy-port to 0) which would also make sense in the mode for
    specific internet initiated traffic you might want to allow in.

    TCP:
        If the tcp connections close gracefully then the entries will remove upon connection closure. 
        if not then there is a 60 minute timeout that will remove the in active state if no traffic seen
        in either direction.

    UDP:
        State will remain active as long as packets tuples matching SRCIP/SPORT/DSTIP/DPORT are seen in
        either direction within 30 seconds.  If no packets seen in either dorection the state will expire.
        If an external packet enters the interface after expire the entry will be deleted.  if an egress
        packet fined a matching expired state it will return the state to active.

    In order to support this per interface rule awareness was added which allows each port range within a prefix
    to match a list of connected interfaces.  On a per interface basis you can decide to honor that list or not via
    a per-prefix-rules setting in the following manner via the zfw utility
    
    singly:
    ```
    sudo zfw -P <ifname>  <this would be set on the wan facing interface so that it would not have access to openziti services unless manully added >
                          <To survive restart this would need to be added to the /opt/opnziti/user/user_rule.sh>
    ```
    or 

    all interfaces:
    ```
    sudo zfw -P all
    ```

    In order to assign 1 to 3 interfaces to a rule you would use the new -N option in combination with the -I i.e.
    to associate the rule to end37 and lo:

    ```
    sudo zfw -I -c 172.16.31.0 -m 24 -l 443 -h 443 -t 44000 -p tcp -N ens37 -N lo
    ```

    You will also need to enable outbound tracking on the external interface.  You can do so with the following:
    Assuming ens33 is your wan facing interface you 

    sudo vi /opt/openziti/etc/ebpf_config.yml

    add a new key ExternalInterfaces like this
    {"InternalInterfaces":[{"Name":"ens37"},{"Name":"ens33"}], "ExternalInterfaces":[{"Name":"ens33"}]}
    
    The above JSON sets up ens33 to be an internal interface (No outbound tracking) and ens33 as an external interface
    with outbound tracking.  It also automatically adds runs the sudo zfw -P ens33 so ens33 requires -N to add inbound
    rules to it and will ignore rules where it is not in the interface list
    


### Manually Detaching from interface:

```bash
sudo zfw --set-tc-filter <interface name>  --direction <ingress | egress> --disable
```

## Ebpf Map User Space Management
---
Example: Insert map entry to direct SIP traffic destined for 172.16.240.0/24


Usage: ./zfw -I <ip dest address or prefix> -m <prefix length> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>

```
sudo ./zfw -I -c 172.16.240.0 -m 24 -l 5060 -h 5060 -t 58997 -p udp
```

As mentioned earlier if you add -r, --route as argument the program will add 172.16.240.0/24 to the "lo" interface if it
does not overlap with an external LAN interface subnet.

Example: Disable ssh from interface.

This will disable default ssh action to pass to ip of local interface and then fall through to rule check instead where a more specific rule could
be applied.  This is a per interface setting and can be set for all interfaces except loopback.

Usage: ./zfw -x <interface-name> | all

```
sudo sudo ./zfw -x ens33
```


Example: Insert map entry to with source filteing to only allow rule for ip source 10.1.1.1/32.

Usage: ./zfw -I -c <ip dest address or prefix> -m <dest prefix len> -o <origin address or prefix> -n <origin prefix len> -l <low_port> -h <high_port> -t <tproxy_port> -p <protocol>

```
sudo sudo ./zfw -I -c 172.16.240.0 -m 24 -o 10.1.1.1 -n 32  -p tcp -l 22 -h 22 -t 0
```

Example: Insert FW rule for local router tcp listen port 443 where local router's tc interface ip address is 10.1.1.1
with tproxy_port set to 0 signifying local connect rule

```
sudo ./zfw -I -c 10.1.1.1 -m 32 -l 443 -h 443 -t 0 -p tcp  
```

Example: Monitor ebpf trace messages

```
sudo zfw -v all
sudo cat /sys/kernel/debug/tracing/trace_pipe
  
<idle>-0       [007] dNs.. 167940.070727: bpf_trace_printk: ens33
<idle>-0       [007] dNs.. 167940.070728: bpf_trace_printk: source_ip = 0xA010101
<idle>-0       [007] dNs.. 167940.070728: bpf_trace_printk: dest_ip = 0xAC10F001
<idle>-0       [007] dNs.. 167940.070729: bpf_trace_printk: protocol_id = 17
<idle>-0       [007] dNs.. 167940.070729: bpf_trace_printk: tproxy_mapping->5060 to 59423

<idle>-0       [007] dNs.. 167954.255414: bpf_trace_printk: ens33
<idle>-0       [007] dNs.. 167954.255414: bpf_trace_printk: source_ip = 0xA010101
<idle>-0       [007] dNs.. 167954.255415: bpf_trace_printk: dest_ip = 0xAC10F001
<idle>-0       [007] dNs.. 167954.255415: bpf_trace_printk: protocol_id = 6
<idle>-0       [007] dNs.. 167954.255416: bpf_trace_printk: tproxy_mapping->22 to 39839

```
Example: Remove previous entry from map


Usage: ./zfw -D -c <ip dest address or prefix> -m <prefix len> -l <low_port> -p <protocol>

```
sudo ./zfw -D -c 172.16.240.0 -m 24 -l 5060 -p udp
```

Example: Remove all entries from map

Usage: ./zfw -F

```
sudo ./zfw -F
```

Example: List all rules in map

Usage: ./zfw -L

```
sudo ./zfw -L
```

target     proto    origin              destination               mapping:                                                   interface list
------     -----    ---------------     ------------------        --------------------------------------------------------- ----------------
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=22:22                TPROXY redirect 127.0.0.1:33381  [ens33,lo]
TPROXY     tcp      0.0.0.0/0           10.0.0.16/28              dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
TPROXY     udp      0.0.0.0/0           172.20.1.0/24             dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=22:22                TPROXY redirect 127.0.0.1:33381  []
TPROXY     tcp      0.0.0.0/0           172.16.1.0/24             dpts=30000:40000          TPROXY redirect 127.0.0.1:33381  []
PASSTHRU   udp      0.0.0.0/0           192.168.3.0/24            dpts=5:7                  PASSTHRU to 192.168.3.0/24       []
PASSTHRU   udp      10.1.1.1/32         192.168.100.100/32        dpts=50000:60000          PASSTHRU to 192.168.100.100/32   []
PASSTHRU   tcp      10.230.40.1/32      192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
TPROXY     udp      0.0.0.0/0           192.168.0.3/32            dpts=5000:10000           TPROXY redirect 127.0.0.1:59394  []
PASSTHRU   tcp      0.0.0.0/0           192.168.100.100/32        dpts=60000:65535          PASSTHRU to 192.168.100.100/32   []
TUNMODE    udp	    0.0.0.0/0           100.64.0.0/10             dpts=1:65535     	        TUNMODE redirect:tun0            []
```
Example: List rules in map for a given prefix and protocol
# Usage: ./zfw -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>
```  
sudo zfw -L -c 192.168.100.100 -m 32 -p udp
```
  
target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- ------------------    
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []


Example: List rules in map for a given prefix
# Usage: ./zfw -L -c <ip dest address or prefix> -m <prefix len> -p <protocol>
```
sudo zfw -L -c 192.168.100.100 -m 32
```

target     proto    origin           destination              mapping:                                                  interface list
------     -----    --------         ------------------       --------------------------------------------------------- -------------------
PASSTHRU   udp      0.0.0.0/0        192.168.100.100/32       dpts=50000:60000 	      PASSTHRU to 192.168.100.100/32     []
PASSTHRU   tcp      0.0.0.0/0        192.168.100.100/32       dpts=60000:65535	      PASSTHRU to 192.168.100.100/32     []

Example: List all interface settings

Usage: ./zfw -L -E
```
sudo ./zfw -L -E
```

lo: 1
--------------------------
icmp echo               :1
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :1
tc egress filter        :0
tun mode intercept      :0
--------------------------

ens33: 3
--------------------------
icmp echo               :0
verbose                 :1
ssh disable             :1
per interface           :1
tc ingress filter       :1
tc egress filter        :1
tun mode intercept      :0
--------------------------

ens37: 4
--------------------------
icmp echo               :0
verbose                 :0
ssh disable             :0
per interface           :0
tc ingress filter       :1
tc egress filter        :0
tun mode intercept      :0
--------------------------

tun0: 9
--------------------------
verbose                 :0
cidr                    :100.64.0.0
mask                    :10
--------------------------
```

Example: Remove all tc-ebpf on router

Usage: ./zfw -Q,--disable-ebpf
```
sudo zfw --disable-ebpf
```
tc parent del : lo
tc parent del : ens33
tc parent del : ens37
removing /sys/fs/bpf/tc/globals/zt_tproxy_map
removing /sys/fs/bpf/tc/globals/diag_map
removing /sys/fs/bpf/tc/globals/ifindex_ip_map
removing /sys/fs/bpf/tc/globals/tuple_count_map
removing /sys/fs/bpf/tc/globals/prog_map
removing /sys/fs/bpf/tc/globals/udp_map
removing /sys/fs/bpf/tc//globals/matched_map
removing /sys/fs/bpf/tc/globals/tcp_map
```


### Openziti router setup:
-comming soon