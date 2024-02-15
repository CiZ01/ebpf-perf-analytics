#! /bin/bash

# this script execute a series of tests, and capture the run_time_ns from bfp stats using bpftool prog show
# it's useful to compare the performace of the xdp kern version white trace,
# I think bpf stats consider the entire time of the xdp program and
# trace function add a lot of time to the execution (maybe)
#

MAX_PRINT=100

num_tests=1
precision=10
output="output.csv"
ifname="veth0"
dest_ip=""
user_space="xdp_cid_user.o"
trace=0

prog=xdp_cid_func

# check sudo permissions
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

while getopts "n:o:i:p::d:t:P:" opt; do
    case $opt in
        n)  # capture the number of tests to run
            num_tests=$OPTARG
        ;;
        o)  # capture the output file name
            output=$OPTARG
            if [ ! -d $(dirname "$output") ]; then
                echo "The output file must be in a valid directory"
                exit
            fi
        ;;
        t)  # capture the user space program
            trace=1
            user_space="${prog%?????}_user_trace.o"
        ;;
        i)  # capture the interface name
            ifname=$OPTARG
        ;;
        d)  # capture the destination ip
            dest_ip=$OPTARG
        ;;
        P)  # capture the print precision
            precision=$OPTARG
        ;;
        p)  # capture the filename
            prog=$OPTARG
            user_space="${prog%?????}_user.o"
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
        ;;
    esac
done



# add header
if [ "$trace" -eq 1 ]; then
    echo "#,MY-VALUE,BPF-STAS" > $output
else
    echo "#,BPF-STAS" > $output
fi

sum=0
last_time=0
tmp_output=$(mktemp)
for i in $(seq 1 "$num_tests" ); do
    if [ "$num_tests" -gt "$MAX_PRINT" ]; then
        if [ $((i % "$precision")) -eq 0 ]; then
            echo "Running test $i"
        fi
    else
        echo "Running test "$i""
    fi
    
    
    ./"$user_space" -i $ifname > "$tmp_output" &
    user_pid=$!
    
    sleep 0.3
    ip netns exec red ping "$dest_ip" -c 1 > /dev/null
    
    last_time=$(bpftool prog show --json name $prog | jq '.run_time_ns')
    
    kill -SIGINT $user_pid || { echo "Error killing the user program"; exit 1; }
    
    # save in the output file
    if [ "$trace" -eq 1 ]; then
        my_value=$(sed -n 2p "$tmp_output")
        echo ""$i","$my_value","$last_time"" >> $output
        continue
    fi
    echo ""$i","$last_time"" >> $output
done

rm $tmp_output
echo "Output saved in $output"
echo "Done"

exit 0
