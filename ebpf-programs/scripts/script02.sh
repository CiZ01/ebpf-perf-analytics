#! /bin/bash

# usage
usage() {
    echo "Usage: $0 -P <prog> [-n <n_pkt>] [-r <reps>] [-o <output>] [-e <event>] [-p <precision>] [-t]"
    echo "  -P <prog>       Program name"
    echo "  -n <n_pkt>      Number of packets to send"
    echo "  -r <reps>       Number of repetitions"
    echo "  -o <output>     Output file"
    echo "  -e <event>      Perf event"
    echo "  -p <precision>  Print progress every <precision> repetitions"
    echo "  -t              Trace userspace program"
    exit 1
}

parse_metric_id() {
    case $event in
        "cycles") METRIC_ID=0;;
        "instructions") METRIC_ID=1;;
    esac
}

#check sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

prog=
userspace=
kernelspace=

reps=100
n_pkt=10000
output="output.csv"
event=cycles
precision=1
fload=
trace=0

PROFILER=/home/cizzo/Scrivania/eBPF/ebpf-perf-analytics/tracing-tools/xdp-introspection/xdp-extrospection/fentry.o
MY_MODULE=mykperf_module
METRIC_ID=0

cleanup() {
    echo "Avvio cleanup"
    kill -INT "$user_pid" || { echo "Error killing userspace"; exit 1; }
    kill -INT "$profiler_pid" || { echo "Error killing profiler"; exit 1; }
    rm -f "$profiler_tmp" "$userspace_tmp" "$ping_log"
}

#check if kernel module is loaded
if [ -z "$(lsmod | grep -o "$MY_MODULE")" ]; then
    echo "Kernel module $MY_MODULE not loaded. Load it and try again"
    exit 1
fi

#check rdpmc permission flag
if [ "$(cat /sys/devices/cpu/rdpmc)" -ne 2 ]; then
    echo "Enable rdpmc by running: echo 2 | sudo tee /sys/devices/cpu/rdpmc"
    exit 1
fi

#check bpf-stats
# if [ ! -z $(sysctl kernel.bpf_stats_enabled | grep -o "[0-9]") ]; then
#     echo "WARNING: bpf_stats_enabled is set. May add overhead."
# fi

#check if fentry alias is already in use
# if [ ! -z "$(type $PROFILER | grep -c "not found")" ]; then
#     echo "Profiler $PROFILER not found. Add it as an alias or change the PROFILER variable"
#     exit 1
# fi

while getopts ":P:r:n:o:e:p:t" opt; do
    case $opt in
        P)
            prog="$OPTARG"
            userspace="${prog%?????}_user.o"
            kernelspace="${prog%?????}_kern.o"
        ;;
        n)
            n_pkt="$OPTARG"
        ;;
        r)
            reps="$OPTARG"
        ;;
        o)
            output="$OPTARG"
        ;;
        e)
            event="$OPTARG"
            parse_metric_id
        ;;
        p)
            precision="$OPTARG"
        ;;
        t)
            trace=1
            userspace="${prog%?????}_user_trace.o"
            kernelspace="${prog%?????}_kern_trace.o"
        ;;
        h)
            usage
        ;;
        \?)
            echo "Invalid option: -$OPTARG"
            exit 1
        ;;
    esac
done

# check output dir
output_dir=$(dirname "$output")
if [ ! -d "$output_dir" ]; then
    echo "Directory $output_dir does not exist"
    exit 1
fi

# check if output file exists
if [ -f "$output" ]; then
    echo "File $output already exists. Overwrite? (y/N)"
    read -r answer
    if [ "$answer" != "y" ]; then
        echo "Exiting"
        exit 1
    fi
fi

# create temp files
profiler_tmp=$(mktemp profiler.XXXXXX)
if [ "$trace" -eq 1 ]; then
    userspace_tmp=$(mktemp user.XXXXXX)
fi
ping_log=$(mktemp ping.XXXXXX)
logger=$(mktemp logger.XXXXXX)



# start xdp prog
if [ "$trace" -eq 1 ]; then
    ./"$userspace" -i veth0 1> $userspace_tmp &
else
    ./"$userspace" -i veth0 &
fi
user_pid=$!

trap 'cleanup; exit 0' INT

echo "Retrieving prog id..."
# while progid != 0
while [ -z "$prog_id" ]; do
    prog_id=$(bpftool prog show name $prog | sed -nE 's/^([0-9]+):.*/\1/p')
    sleep 0.1
done

echo "Program loaded and attached: $prog_id"

# add header
if [ "$trace" -eq 1 ]; then
    echo "BPFTOOL-STAT $event, MY-BPFTOOL-STAT ,MY-STATS" > "$output"
else
    echo "BPFTOOL-STAT $event, MY-BPFTOOL-STAT" > "$output"
fi


for i in $(seq 1 "$reps"); do
    sum=0
    if [ $((i % precision)) -eq 0 ]; then
        echo "Repetition $i"
    fi
    
    # start profiler
    $PROFILER -i "$prog_id" -m "$METRIC_ID" > $profiler_tmp &
    profiler_pid=$!
    
    sleep 1
    
    # send ping
    ip netns exec red ping '192.168.0.1' -c "$n_pkt" -f > $ping_log 2>&1
    
    kill -INT "$profiler_pid" || { echo "Error killing profiler"; cleanup; exit 1; }
    
    #retrieve profiler value
    profiler_output=$(cat "$profiler_tmp" | sed -nE "s/([0-9]+) $event .* ([0-9]+) my_value.*/\1 \2/p")
    
    profiler_value=$(echo "$profiler_output" | awk '{print $1}')
    if [ -z "$profiler_value" ]; then
        echo "[ERR] [profiler] zero value at repetition $i" >> "$logger"
        cat "$profiler_tmp" >> "$logger"
        echo "[ERR] [profiler] zero value at repetition $i"
    fi
    
    #retrieve profiler my value
    profiler_my_value=$(echo "$profiler_output" | awk '{print $2}')
    if [ -z "$profiler_my_value" ]; then
        echo "[ERR] [my profiler] zero value at repetition $i" >> "$logger"
        cat "$profiler_tmp" >> "$logger"
        echo "[ERR] [my profiler] zero value at repetition $i"
    fi
    
    # retrieve userspace value
    if [ "$trace" -eq 1 ]; then
        # count lines and check if it's the same as n_pkt
        line_c=$(wc -l "$userspace_tmp" | awk '{print $1}')
        if [ "$line_c" != "$n_pkt" ]; then
            echo "[ERR] [userspace] wrong number of packets at repetition $i: $line_c" >> "$logger"
            echo "[ERR] [userspace] wrong number of packets at repetition $i: $line_c"
        fi
        
        #awk didn't work, even with perl didn't work
        while read line; do
            my_value=$((my_value + line))
        done < "$userspace_tmp"
        if [ -z "$my_value" ]; then
            echo "[ERR] [usersapce] zero value at repetition $i" >> "$logger"
            echo "[ERR] [userspace] zero value at repetition $i"
        fi
        echo "$profiler_value, $profiler_my_value, $my_value" >> "$output"
        my_value=0
        > "$userspace_tmp"
        
    else
        echo "$profiler_value, $profiler_my_value" >> "$output"
    fi
    
done

echo "Output written to $output"

if [ -s "$logger" ]; then
    echo "Some errors occurred. Check $logger"
else
    rm "$logger"
fi

cleanup

exit 0
