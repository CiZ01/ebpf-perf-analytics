#!/bin/bash

# script to run XDP program test
# accuracy test, sampled vs all packets

ifname=enp129s0f0np0
prog=xdp_pass_func
event=instructions
duration=2 #seconds
load=0
filename=
tag=main

# get opts
while getopts "i:p:" opt; do
    case $opt in
        i)
            ifname=$OPTARG
        ;;
        p)
            prog=$OPTARG
        ;;
        d)
            duration=$OPTARG
        ;;
        l)
            load=1
        ;;
        f)
            filename=$OPTARG
        ;;
        e)
            event=$OPTARG
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
        ;;
    esac
done

if [ $load -eq 1 ] && [ -z $filename ]; then
    echo "Please provide a filename to load"
    exit 1
fi

#tmp file
tmp_loader=$(mktemp /tmp/loader.XXXXXX)


# start trex

# ...

# start loader
sudo loader-stats -i $ifname -c -a -e $event -n $prog > $tmp_loader &
loader_pid=$!

# wait for duration
sleep $duration

# stop loader
kill -INT "$loader_pid"

wait $loader_pid


# retrieve stats
total_run_cnt=$(cat $tmp_loader | sed -n "s/Total run_cnt: \([0-9.]\+\).*/\1/p")

data=$(grep "$tag.*" $tmp_loader)
echo $data

# retrieve run count
event_run_cnt=$(echo $data | sed -n 's/.* \([0-9.]\+\) runs.*/\1/p')

#retrieve event count
event_value_sum=$(echo $data | sed -n "s/.* "$tag": \([0-9.]\+\).*/\1/p")

# retrieve x pkt
event_xpkt=$(echo $data | sed -n "s/.*\([0-9.]\+\)\/pkt.*/\1/p")

# event_cnt/run_cnt percentage
event_pct=$(echo $event_run_cnt/$total_run_cnt*100 |  bc)

echo "run_cnt=$event_run_cnt"
echo "event_cnt=$event_value_sum"
echo "event_xpkt=$event_xpkt"
echo "event_pct=$event_pct"
echo "total_run_cnt=$total_run_cnt"

# ...

# close loader

# retrieve stats

exit 0

