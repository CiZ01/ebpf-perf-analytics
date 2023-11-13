#! /bin/bash

source $(dirname "$0")/__pretty_func.sh
# TODO: controlla se i peer specificati per ogni interfaccia siano creati nei namespace


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
        if [ "$ipv6" != "null" ]; then
            ip netns exec $ns_name ip -6 addr add $ipv6 dev $veth_name || { echo "Errore durante l'assegnazione di $ipv6 a $veth_name"; exit 1; }
        fi
        
        # set up veth
        ip netns exec $ns_name ip link set dev $veth_name up || { echo "Errore durante l'attivazione di $veth_name"; exit 1; }
    done
    
}

load_namespace(){
    JSON_FILENAME=$1
    for ((i = 0; i < $(jq length $JSON_FILENAME); i++)); do
        namespace_config=$(jq -r ".[$i]" $JSON_FILENAME)
        
        if [ $2 == "-v" ]; then
            echo "$namespace_config"
        fi
        
        ns_name=$(echo $namespace_config | jq -r '.namespace')
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
        echo "$ns_name is created"
    done
    
}