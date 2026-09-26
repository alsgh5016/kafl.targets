#!/bin/bash

# workaround issue https://github.com/hashicorp/vagrant/issues/13193

ip_address=$(vagrant winrm-config 2>/dev/null | awk '/HostName/{print $2; exit}')

# Vagrant resolves the guest address from libvirt's DHCP lease database. A
# domain resumed from a snapshot keeps the address it already holds and never
# re-DHCPs, so once that lease has aged out of the database vagrant reports no
# address at all. The playbook below would then run against an empty inventory
# ("skipping: no hosts matched") and exit 0, silently provisioning nothing.
# Fall back to looking the address up in the host's neighbour table by the
# domain's MAC.
if [ -z "$ip_address" ]; then
    id_file=$(ls .vagrant/machines/*/libvirt/id 2>/dev/null | head -1)
    if [ -n "$id_file" ]; then
        iflist=$(virsh -c qemu:///session domiflist "$(cat "$id_file")" 2>/dev/null)
        mac=$(echo "$iflist" | awk 'NR>2 && NF>=5 {print $5; exit}')
        bridge=$(echo "$iflist" | awk 'NR>2 && NF>=5 {print $3; exit}')
        if [ -n "$mac" ]; then
            ip_address=$(ip -4 neigh show | awk -v m="$mac" 'index($0, m) {print $1; exit}')

            # The neighbour table only knows hosts this machine has talked to
            # recently, which is not the case for a worker it has not reached
            # yet. Probe the bridge subnet to populate it: Windows drops the
            # inbound ICMP, but it still answers the ARP request that precedes
            # it, and the resulting neighbour entry is all we need.
            if [ -z "$ip_address" ] && [ -n "$bridge" ]; then
                cidr=$(ip -4 -o addr show dev "$bridge" 2>/dev/null | awk '{print $4; exit}')
                prefix=${cidr%/*}
                prefix=${prefix%.*}
                if [ -n "$prefix" ]; then
                    for octet in $(seq 1 254); do
                        ping -c1 -W1 "${prefix}.${octet}" >/dev/null 2>&1 &
                    done
                    wait
                    ip_address=$(ip -4 neigh show | awk -v m="$mac" 'index($0, m) {print $1; exit}')
                fi
            fi
        fi
    fi
fi

if [ -z "$ip_address" ]; then
    echo "ERROR: could not determine the guest's WinRM address." >&2
    echo "       Neither 'vagrant winrm-config' nor the neighbour table knows it." >&2
    echo "       The VM must be running and reachable before provisioning." >&2
    exit 1
fi

# WinRM lib doesn't honor no_proxy
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy

ansible-playbook -i "${ip_address}," \
    -e ansible_connection=winrm \
    -e ansible_port=5985 \
    -e ansible_winrm_transport=basic \
    -e ansible_winrm_scheme=http \
    -e ansible_shell_type=powershell \
    -e ansible_user=vagrant \
    -e ansible_password=vagrant \
    setup_target.yml $*
