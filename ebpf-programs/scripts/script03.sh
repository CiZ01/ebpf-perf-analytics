#! /bin/bash

filename=
event=cycles
prog_sec=xdp
ifname=
reps=1000
n_pkt=1000
ip_dest=
output=output.csv
precision=10
perf=0

usage(){
    echo "Usage: $0 -i <ifname> -f <filename> -P <prog_sec> -e <event> -r <reps> -n <n_pkt> -d <ip_dest> -o <output> -p <precision> -x"
    echo "  -i <ifname>      Interface name"
    echo "  -f <filename>    BPF program filename"
    echo "  -P <prog_sec>    Program section [default: xdp]"
    echo "  -e <event>       Perf event [default: cycles]"
    echo "  -r <reps>        Number of repetitions [default: 1000]"
    echo "  -n <n_pkt>       Number of packets to send [default: 1000]"
    echo "  -d <ip_dest>     Destination IP"
    echo "  -o <output>      Output file [default: output.csv]"
    echo "  -p <precision>   Print progress every <precision> repetitions [default: 10]"
    echo "  -x               Use perf"
    exit 1
}

cleanup(){
    rm $tmp_stats
    if [ ! -z perf ]; then
        rm $perf_tmp
    fi
    kill -INT $loader_pid
    exit 0
}

while getopts ":i:f:e:x:P:r:n:d:o:p:" opt; do
    case $opt in
        i)
            ifname=$OPTARG
        ;;
        f)
            filename=$OPTARG
        ;;
        P) #prog sec
            prog_sec=$OPTARG
        ;;
        e)
            #IFS=','
            #read -ra $events <<< "$OPTARG"
            event=$OPTARG
        ;;
        r) # repetitions
            reps=$OPTARG
        ;;
        n) # number of packets
            n_pkt=$OPTARG
        ;;
        x)
            perf=1
        ;;
        d)
            ip_dest=$OPTARG
        ;;
        o)
            output=$OPTARG
        ;;
        p)
            precision=$OPTARG
        ;;
        ?) echo "Invalid option: -$OPTARG" ;;
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
        exit 1
    fi
fi

# tmp file
tmp_stats=$(mktemp stats.$(date +%Y%m%d%H%M%S).XXX)
if [ ! -z perf ]; then
    perf_tmp=$(mktemp perf.$(date +%Y%m%d%H%M%S).XXX)
fi


# load csv header
if [ ! -z perf ]; then
    echo "PERF-STATS, VALUE" > $output
else
    echo "value" > $output
fi

#set trap
trap cleanup INT

# run loader and stats in backgroud
loader-stats -i "$ifname" -f "$filename" -m skb -P "$prog_sec" -e "$event" 1> "$tmp_stats" &
loader_pid=$!

# get prog id, wait until it is loaded
prog_id=
while [ -z "$prog_id" ]; do
    prog_id=$(rg '\[INFO\]: Attached program id: ([0-9]+)' -r '$1' "$tmp_stats")
done

echo "Program id: $prog_id"

total_value=0
line_cnt=0
for i in $(seq 1 "$reps"); do
    if [ $((i % precision)) -eq 0 ]; then
        echo "Repetition $i"
    fi
    
    # if perf is enabled, run perf stat
    if [ ! -z perf ]; then
        perf stat -e "$event" -b "$prog_id" 2> "$perf_tmp" &
        perf_pid=$!
        sleep 0.5
    fi
    
    ip netns exec red ping "$ip_dest" -c "$n_pkt" -f > /dev/null
    
    # get stats and get even lines
    total_value=$(awk 'match($0, /[0-9]+/) { sum += substr($0, RSTART, RLENGTH) } END { print sum }' "$tmp_stats")
    
    if [ ! -z perf ]; then
        kill -INT $perf_pid
        wait "$perf_pid"
        perf_value=$(sed -n "/$event/s/^\s*\([0-9.]*\)\s*$event.*$/\1/p" "$perf_tmp")
        if [ -z "$perf_value" ]; then
            echo "[ERR] [perf] zero value at repetition $i"
        fi
        #remove dots
        perf_value=$(echo "$perf_value" | tr -d .)
        
        echo "$perf_value, $total_value" >> $output
    else
        echo $total_value >> $output
    fi
    
    # clean file stats
    echo > "$tmp_stats"
    awk 'BEGIN { sum = 0 }'
done

cleanup
