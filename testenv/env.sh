#! /bin/bash
# the script is used to create namespaces and veth pairs.
# It should be run as root.

source $(dirname "$0")/load_config.sh

create_namespace(){
    i=1
    for ns in "$@"
    do
        veth_name=veth$((i - 1))
        # create namespace
        ip netns add $ns
        
        # create veth pair
        ip link add $veth_name type veth peer name veth$i
        
        # add veth to namespace
        ip link set $veth_name netns $ns
        
        # set ipv4 address
        ip netns exec $ns ip addr add 192.168.$i.1/24 dev $veth_name
        
        # set ipv6 address
        # TODO
        #ip netns exec $ns ip -6 addr add
        
        # set up veth
        ip netns exec $ns ip link set dev $veth_name up
        
        i=$((i+1))
        
        
        __get_pretty_prompt_name $ns
        ns_ps_name=$ns
        if [ $pretty_prompt_name != "null" ];
        then
            ns_ps_name=$pretty_prompt_name
        fi
        
        echo "export PS1='$ns_ps_name'" > ."$1"_bashrc
        echo "$ns is created"
    done
}

delete_namespace(){
    case $1 in
        all)
            shift
            if [ "$1" != "-f" ];
            then
                echo "Warning: you are going to delete ALL namespaces."
                echo "Are you sure to delete ALL namespaces? (y/n)"
                read ans
                
                if [[ $ans != y ]]  && [[ ! -z $ans ]];
                then
                    exit 1
                fi
            fi
            
            for ns in $(ip netns list | awk '{print $1}')
            do
                ip netns exec $ns rm ~/."$ns"_bashrc
                ip netns del $ns
                echo "delete namespace $ns"
            done
        ;;
        *)
            if [ "$1" != "-f" ];
            then
                echo "Warning: you are going to delete ALL namespaces."
                echo "Are you sure to delete ALL namespaces? (y/n)"
                read ans
                if [[ $ans != y ]]  && [[ ! -z $ans ]];
                then
                    exit 1
                fi
            else
                shift
            fi
            
            if [ -z "$@" ];
            then
                echo "Error: you should specify the namespaces you want to delete."
                echo "Or you can use 'all' to delete all namespaces."
                exit 1
            fi
            
            for ns in "$@"
            do
                err=$(ip netns del $ns)
                if [ -z $err ];
                then
                    echo "namespace $ns deleted!"
                fi
            done
        ;;
    esac
}




enter_namespace(){
    
    if [ $# -eq 0 ] && [[ $(ip netns list | awk '{print $1}' | wc -l) -gt 1 ]];
    then
        echo "There are more than one namespaces, you should specify one."
        exit 1
    fi
    
    # if there is only one namespace, enter it directly
    if [[ $# -eq 0 ]] && [[ $(ip netns list | awk '{print $1}' | wc -l) -eq 1 ]];
    then
        ns1=$(ip netns list | awk '{print $1}')
        
        ip netns exec $ns1 bash --rcfile ."$ns1"_bashrc
        exit 0
    fi
    
    # if there are more than one namespaces, choose one
    if [ $# -eq 1 ];
    then
        ip netns exec $1 bash --rcfile ~/."$1"_bashrc
    fi
    exit 0
}

# TODO
get_namespace(){
    if [ "$1" == "-v" ];
    then
        for ns in $(ip netns list | awk '{print $1}')
        do
            ip netns list | rg --colors match:fg:blue "$ns .*"
            ip netns exec $ns ip a | perl -nle 'print "    $1  $2" if /(\d{0,3}: .*):.*| (inet.*)/gm'
            echo "----------------------------------------------------------------------------"
        done
        exit 0
    fi
    
    if [ "$1" == "-vv" ];
    then
        for ns in $(ip netns list | awk '{print $1}')
        do
            ip netns list | rg --colors match:fg:blue "$ns .*"
            ip netns exec $ns ip a | perl -nle 'print "    $1  $2" if /(\d{0,3}: .*):.*|(prog.*\d*).* |(inet.*)/gm'
            
            echo "----------------------------------------------------------------------------"
        done
        exit 0
    fi
    
    for ns in $(ip netns list | awk '{print $1}')
    do
        ip netns list | rg --colors match:fg:blue "$ns .*"
    done
    exit 0
}

load_config(){
    
    if [ $1 == "-f" ];
    then
        shift
        CONFIG_PATH=$1

        # if -v is specified, print the config file
        load_namespace $CONFIG_PATH $2
        exit 0
    fi
    
    load_namespace config.json $1
}


case $1 in
    create)
        shift
        create_namespace $@
    ;;
    enter)
        shift
        enter_namespace $@
    ;;
    config)
        shift
        load_config $@
    ;;
    get)
        shift
        get_namespace $@
    ;;
    delete)
        shift
        delete_namespace $@
    ;;
    *)
        echo "Usage: $0 {create|delete} namespace1 namespace2 ..."
        exit 1
esac



