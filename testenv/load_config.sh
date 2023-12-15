#! /bin/bash

source $(dirname "$0")/__pretty_func.sh
# TODO: controlla se i peer specificati per ogni interfaccia siano creati nei namespace

declare -A mac_address

get_mac_address() {
    local namespace=$1
    local interface=$2
    
    # Recupera il MAC address usando ip link show
    mac_address=$(ip netns exec $namespace ip link show $interface | awk '/link\/ether/ {print $2}')
    
    if [ -z "$mac_address" ]; then
        echo "Errore: Impossibile recuperare l'indirizzo MAC per l'interfaccia $interface nel namespace $namespace."
        exit 1
    fi
    
    echo $mac_address
}

load_arp(){
    # retrieve mac address for neighbors
    mac_address=$(get_mac_address $ns_name $veth_name)
    
    
    # add ipv4 route
    ipv4_route=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv4_route // "null"' $JSON_FILENAME)
    if [ "$ipv4_route" != "null" ];
    then
        ipv4_route=$(echo $ipv4_route | jq -r '.[]')
        for route in $ipv4_route;
        do
            ip netns exec $ns_name ip route add $route dev $veth_name || { echo "Errore durante l'aggiunta della rotta $ipv4_route"; exit 1; }
        done
    fi
    
    # add ipv6 route
    ipv6_route=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv6_route // "null"' $JSON_FILENAME)
    if [ "$ipv6_route" != "null" ];
    then
        ipv6_route=$(echo $ipv6_route | jq -r '.[]')
        for route in $ipv6_route;
        do
            ip netns exec $ns_name ip -6 route add $route dev $veth_name || { echo "Errore durante l'aggiunta della rotta $ipv6_route"; exit 1; }
        done
    fi
    
    # add ipv4 neighbour
    ipv4_arp=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv4_arp // "null"' $JSON_FILENAME)
    if [ "$ipv4_arp" != "null" ];
    then
        ipv4_arp=$(echo $ipv4_arp | jq -r '.[]')
        for neighbor in $ipv4_arp;
        do
            ip netns exec $ns_name arp add $neighbor lladdr $mac_address || { echo "Errore durante l'aggiunta dell'indirizzo ip $ipv4_arp alla tabella arp"; exit 1; }
        done
    fi
    
    # add ipv6 neighbour
    ipv6_neigh=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv6_neig // "null"' $JSON_FILENAME)
    if [ "$ipv6_neighbor" != "null" ];
    then
        ipv6_neighbor=$(echo $ipv6_neighbor | jq -r '.[]')
        for neighbor in $ipv6_neighbor;
        do
            ip netns exec $ns_name ip -6 neigh add $neighbor lladdr $mac_address dev $veth_name || { echo "Errore durante l'aggiunta del neighbor $ipv6_neighbor"; exit 1; }
        done
    fi
}

load_peer(){
    JSON_FILENAME=$1
    ns_name=$2
    veth_name=$3
    
    veth_peer=$(jq --arg ns "$ns_name" --arg veth "$veth_name" -r '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .veth_peer' $JSON_FILENAME)
    if [ "$veth_peer" == "null" ];
    then
        ip link add $veth_name type dummy
        return
    else
        veth_peer=$(echo $veth_peer | jq -r '.[]')
    fi
    
    prev_veth=$veth_name
    
    # ERROR: DONT WORK WITH MORE THAN 1 PEER
    for peer in $veth_peer;
    do
        ip link add $prev_veth type veth peer name $peer  || { echo "Errore durante la creazione del peer: $peer"; exit 1; }
        prev_veth=$peer
    done
}


load_veths(){
    JSON_FILENAME=$1
    ns_name=$2
    veths=$(jq --arg ns "$ns_name" '.[] | select(.namespace == $ns) | .veths // null' $JSON_FILENAME)
    
    if [ "$veths" == "null" ];
    then
        return
    fi

    # iterate over veths
    for veth_name in $(echo "$veths" | jq -r '.[] | .veth_name');
    do
        # load all peers for the current veth
        load_peer $JSON_FILENAME $ns_name $veth_name
        
        # add veth to namespace
        ip link set $veth_name netns $ns_name || { echo "Errore durante l'aggiunta di $veth_name a $ns_name"; exit 1; }
        
        # add ipv4 address if specified
        ipv4=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv4 // "null"' $JSON_FILENAME)
        if [ $ipv4 != "null" ]; then
            ip netns exec $ns_name ip addr add $ipv4 dev $veth_name || { echo "Errore durante l'assegnazione di $ipv4 a $veth_name"; exit 1; }
        fi
        
        # add ipv6 address if specified
        ipv6=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv6 // "null"' $JSON_FILENAME)
        if [ $ipv6 != "null" ]; then
            ip netns exec $ns_name ip -6 addr add $ipv6 dev $veth_name || { echo "Errore durante l'assegnazione di $ipv6 a $veth_name"; exit 1; }
        fi
        
        # set up veth
        ip netns exec $ns_name ip link set dev $veth_name up || { echo "Errore durante l'attivazione di $veth_name"; exit 1; }
        
        # add ipv4 route
        ipv4_route=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv4_route // "null"' $JSON_FILENAME)
        if [ "$ipv4_route" != "null" ];
        then
            ipv4_route=$(echo $ipv4_route | jq -r '.[]')
            for route in $ipv4_route;
            do
                ip netns exec $ns_name ip route add $route dev $veth_name || { echo "Errore durante l'aggiunta della rotta $ipv4_route"; exit 1; }
            done
        fi
        
        # add ipv6 route
        ipv6_route=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv6_route // "null"' $JSON_FILENAME)
        if [ "$ipv6_route" != "null" ];
        then
            ipv6_route=$(echo $ipv6_route | jq -r '.[]')
            for route in $ipv6_route;
            do
                ip netns exec $ns_name ip -6 route add $route dev $veth_name || { echo "Errore durante l'aggiunta della rotta $ipv6_route"; exit 1; }
                
            done
        fi
    done
}

load_gateway(){
    for ((i = 0; i < $( jq length $JSON_FILENAME); i++)); do
        local namespace_config=$(jq -r ".[$i]" $JSON_FILENAME)
        
        local ns_name=$( echo $namespace_config | jq -r '.namespace' )
        local veths=$(jq --arg ns "$ns_name" '.[] | select(.namespace == $ns) | .veths // null' $JSON_FILENAME)
        if [ "$veths" == "null" ];
        then
            return
        fi
        
        # iterate over veths
        for veth_name in $(echo "$veths" | jq -r '.[] | .veth_name');
        do
            # add ipv4 gateway
            ipv4_gateway=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv4_gateway // "null"' $JSON_FILENAME)
            if [ "$ipv4_gateway" != "null" ];
            then
                ip netns exec $ns_name ip route add $ipv4_gateway dev $veth_name || { echo "Errore durante l'aggiunta della route ipv4 all'interfaccia $veth_name"; exit 1; }
                ip netns exec $ns_name ip route add default via $ipv4_gateway || { echo "Errore durante l'aggiunga del gateway ipv4 all'interfaccia $veth_name"; exit 1; }
            fi
            
            # add ipv6 gateway
            ipv6_gateway=$( jq -r --arg ns "$ns_name" --arg veth "$veth_name" '.[] | select(.namespace == $ns) | .veths[] | select(.veth_name == $veth) | .ipv6_gateway // "null"' $JSON_FILENAME)
            if [ "$ipv6_gateway" != "null" ];
            then
                ip netns exec $ns_name ip -6 route add $ipv6_gateway dev $veth_name || { echo "Errore durante l'aggiunta della route ipv6 all'interfaccia $veth_name"; exit 1; }
                ip netns exec $ns_name ip -6 route add default via $ipv6_gateway || { echo "Errore durante l'aggiunta del gateway ipv6 all'interfaccia $veth_name"; exit 1; }
            fi
        done
    done
}

load_namespace(){
    JSON_FILENAME=$1
    for ((i = 0; i < $(jq length $JSON_FILENAME); i++)); do
        namespace_config=$(jq -r ".[$i]" $JSON_FILENAME)
        
        if [ "$2" == "-v" ]; then
            echo "$namespace_config"
        fi
        
        ns_name=$(echo $namespace_config | jq -r '.namespace' )
        if [ $ns_name == "null" ];
        then
            echo "Errore: nome del namespace non specificato: $ns_name"
            exit 1
        fi
        
        ip netns add $ns_name || { echo "Errore durante la creazione del namespace"; exit 1; }
        
        __get_pretty_prompt_name "$namespace_config" $JSON_FILENAME || { echo "Errore durante la lettura del nome del namespace"; exit 1; }
        ns_prompt=$ns_name
        if [ ! -z "$pretty_prompt" ];
        then
            ns_prompt=$pretty_prompt
        fi
        
        echo "export PS1='$ns_prompt'" > ~/."$ns_name"_bashrc
        load_veths $JSON_FILENAME $ns_name
        
        # setting ip forwarding
        ip netns exec $ns_name sudo sysctl net.ipv4.conf.all.forwarding=1
        ip netns exec $ns_name sudo sysctl net.ipv6.conf.all.forwarding=1
        
        
        echo "$ns_name created"
    done
    
    # now add the gateway to every namespaces
    echo "Loading gateway..."
    load_gateway $JSON_FILENAME
    
    exit 0
}
