#!/bin/bash
# Name: docker-Firewall.sh
# Purpose: Setting up comfortably the DOCKER-USER iptables chain to protect docker advertised ports from attacks from Internet
# docker-Firewall.sh {ON|OFF}
# Since this DOCKER-USER iptables chain is called at the very beginning of FORWARD chain.
# it only affects the incoming packets destined to Docker advertised internal addresses & ports
# and not any packets destined to local applications like SSH, HTTP etc.
# Changes: 26.05.2020   Initial creation of script
# Author: Michel Bisson(michel@linuxint.com)
#-----------------------------------------------------------------------------
# Constants
#set -x -e
iptables=$(which iptables)
ext_if="eth0"
# ---------------------- User Definable variables -------------------------
# Internal networks: 127.0.0.0/16 192.168.0.0/16 172.16.0.0/12
internal_networks="127.0.0.0/16 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"
# Needed for returning connections
docker_network="172.16.0.0/12"
 
# Hosts that are trusted and allowed to access all Docker advertised ports
# Format: IPAddr[:{udp|tcp}:port]
# This can be:
# Single host address(eg. 197.206.101.184): This Internet host will have full access to all docker advertised ports
# Network(eg. 123.123.123.0/24): All Internet hosts in the network will have full access
# Network or Host with port type & port number: (eg. 197.206.101.184:tcp:1205 123.123.123.0/24:udp:3000): Internet Host or all hosts in network will be limited to access to defined port type and port number. 
 
# In the following examples of 'trusted_hosts' are:
# (56.143.177.17) host get full access to all docker advertised ports
# (18.175.184.18:udp:3001) host gets access to only udp port 3001
# (123.123.123.12/31:tcp:3000) both hosts 123.123.123.12 and 123.123.123.13 get access to only tcp port 3000
 
trusted_hosts="192.198.59.145/29 107.77.0.1/16 166.175.0.1/16 166.170.0.1/16"
 
# Ports (separated by spaces) that are allowed to be access by the whole Internet.
# This can be used for temporarily test a container from an not-trusted host or simply permanently open it to Internet
open_UDP_ports=""
open_TCP_ports="80 443"
# ------------------------- END User Definable variables -----------------------
 
#Functions
function usage() {
    echo "ERROR: Wrong number of arguments(URLs)."
    echo "Syntax: docker-Firewall.sh {ON|OFF}"
    exit 1
}
 
valid_cidr_network() {
  local ip="${1%/*}"    # strip bits to leave ip address
  local bits="${1#*/}"  # strip ip address to leave bits
  local IFS=.; local -a a=($ip)
 
  # Sanity checks (only simple regexes)
  [[ $ip =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  [[ $bits =~ ^[0-9]+$ ]] || return 1
  [[ $bits -le 32 ]] || return 1
 
  # Create an array of 8-digit binary numbers from 0 to 255
  local -a binary=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})
  local binip=""
 
  # Test and append values of quads
  for quad in {0..3}; do
    [[ "${a[$quad]}" -gt 255 ]] && return 1
    printf -v binip '%s%s' "$binip" "${binary[${a[$quad]}]}"
  done
 
  # Fail if any bits are set in the host portion
  [[ ${binip:$bits} = *1* ]] && return 1
 
  return 0
}
 
# check the arguments, min 1
if [ $# -lt 1 ]; then usage ; fi
 
# Convert the argument to capital letters
arg=$(echo $1 | tr 'a-z' 'A-Z')
 
# The script first wipes out any already existing rules
$iptables -F DOCKER-USER
 
case $arg in
    ON) # Activate the firewall
 
        # ------------- Start Firewall here
 
        # Here are the rules to fill into the empty chain DOCKER-USER
 
        # Allow Internal Networks
        for network in $internal_networks ; do
            $iptables -A DOCKER-USER -s $network -j RETURN
        done
 
       # Allow already estabilished connection - returning packets
       $iptables -A DOCKER-USER -d $docker_network -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
 
        # Allow trusted hosts or networks with or without ports
        if (echo $trusted_hosts | grep -q '[0-9]'); then
            for host in $trusted_hosts ; do
                if (echo $host | grep -q ':'); then
                    addr=$(echo $host | cut -d: -f1)
                    type=$(echo $host | cut -d: -f2)
                    port=$(echo $host | cut -d: -f3)
                    # Verifying the validity of the info and entering the rule if all ok
                    # Add /32 to single non-CIDR address
                    if ! (echo $addr | grep -q '/'); then addr=${addr}/32; fi
                    if (valid_cidr_network $addr) ; then
                        ptype=$(echo $type | tr 'A-Z' 'a-z')
                        if $(echo $ptype | egrep -q 'tcp|udp'); then
                            if (echo "$port" | egrep -q '^[0-9]+$'); then
                                $iptables -A DOCKER-USER -i $ext_if -s $addr -p $ptype --dport $port -j RETURN
                            else
                                echo "ERROR: Wrong port number:$port. It should be a pure integer. e. '1234'"
                            fi
                        else
                            echo "ERROR: Wrong 'type' of port:$ptype. Should be 'tcp' or 'udp'"
                        fi
                    else
                        echo "Error: Wrong type of CIDR host/network address:$addr. Should be CIDR conform eg. '123.123.123.0/24' or '123.123.123.123'"
                    fi
                else
                    $iptables -A DOCKER-USER -i $ext_if -s $host -j RETURN
                fi
            done
        fi
 
        # open UDP ports
        if (echo $open_UDP_ports | grep -q '[0-9]'); then
            for UDP_port in $open_UDP_ports; do
                $iptables -A DOCKER-USER -i $ext_if -p udp --dport $UDP_port -j RETURN
            done
        fi
 
        # open TCP ports
        if (echo $open_TCP_ports | grep -q '[0-9]'); then
            for TCP_port in $open_TCP_ports; do
                $iptables -A DOCKER-USER -i $ext_if -p udp --dport $TCP_port -j RETURN
            done
        fi
 
        # Last rules: log remaining packets and DROP ALL ------------
        $iptables -A DOCKER-USER -j LOG --log-prefix "end-DOCKER-USER "
        $iptables -A DOCKER-USER -j DROP
        ;;
 
    OFF) # Turn OFF the firewall and let all packet through(RETURN)
        $iptables -A DOCKER-USER -j RETURN
        ;;
 
    *) usage
        ;;
esac
 
# Show content of DOCKER-USER Chain
$iptables -S DOCKER-USER
#eof