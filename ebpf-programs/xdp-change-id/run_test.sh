#! /bin/bash

USAGE="Usage: run_test.sh <data_in> -o <output> -r <reps> -n <num_tests> -p <prog> [ -P <precision> -t]"

PRINT_MAX_VALUE=100
print_count=10

prog=xdp_cid_func
user_prog=xdp_cid_user.o
runner=xdp_cid_test_run.o
output=test.csv
ifname=veth0
reps=1
num_tests=1
fdata_in=$1
shift

fsize=$(stat -c%s "$fdata_in")

if [ -z "$1" ]; then
    echo $USAGE
    exit 1
fi

# ACCUMULATE OPTIONS
ACC_FLAG=0
acc_my_run=0
acc_bpftool_run=0

# OTHER FLAGS
verbose=0

# get options
while getopts "ho:p:r:n:aP:tvi:" option; do
    case $option in
        o)
            output="$OPTARG"
            if [ ! -d $(dirname "$output") ]; then
                echo "Error: output directory does not exist"
                exit 1
            fi
        ;;
        i)
            ifname="$OPTARG"
        ;;
        r)
            reps="$OPTARG"
        ;;
        n)
            num_tests="$OPTARG"
        ;;
        a)
            ACC_FLAG=1
        ;;
        P)
            print_count="$OPTARG"
        ;;
        p)
            prog="$OPTARG"
            runner="${prog%?????}_run.o"
            user_prog="${prog%?????}_user.o"
            # si rompe se non metti prima la -p e poi -t
        ;;
        t)
            runner="${prog%?????}_test_run.o"
        ;;
        v)
            verbose=1
        ;;
        h)
            echo $USAGE
        ;;
        \?)
            echo "Invalid option: -"$OPTARG"" >&2
        ;;
    esac
done

# add info to output file
echo " | size: "$fsize" bytes, nreps: $reps, num_test: "$num_tests", acc: $ACC_FLAG |" > $output

# add header to output file
echo "my-test-run, bpftool-test-run" >> $output


# load progam and get id
# I need to load user space for bpftool prog run
./"$user_prog" -i "$ifname" > /dev/null &
user_pid=$!
if [ -z "$user_pid" ]; then
    echo "Error: failed to load program"
    exit 1
fi

trap "kill -9 $user_pid; exit 1" SIGINT

prog_id=$(bpftool prog show | sed -n "s/^\([0-9]\+\):.*name $prog.*/\1/p")
if [ -z "$prog_id" ]; then
    echo "Error: program not loaded"
    exit 1
fi

if [ $verbose -eq 1 ]; then
    echo "Program loaded with id: $prog_id"
    echo "runner: $runner, prog: $prog"
    echo "Run test with data_in: $fdata_in"
    echo "fsize: "$fsize" bytes"
    echo "output: $output"
    echo "reps: $reps"
    echo "num_tests: $num_tests"
    echo "ACC_FLAG: $ACC_FLAG"
fi

for i in $(seq 1 $num_tests); do
    if [ $num_tests -gt "$PRINT_MAX_VALUE" ]; then
        if [ $((i % "$print_count")) -eq 0 ]; then
            echo "Run test $i"
        fi
    else
        echo "Run test $i"
    fi
    
    my_value=$(./"$runner" "$ifname" $fdata_in $reps -l)
    if [ -z "$my_value" ]; then
        echo "Error: my test failed: "$my_value""
        kill -9 $user_pid
        exit 1
    fi
    
    bpftool_value=$(bpftool prog run id $prog_id data_in $fdata_in repeat $reps | sed -n "s/.*: \([0-9]\+\)ns/\1/p")
    if [ -z "$bpftool_value" ]; then
        echo "Error: bpftool test failed"
        kill -9 $user_pid
        exit 1
    fi
    # add to csv
    echo "$my_value, $bpftool_value" >> $output
    
    if [ $ACC_FLAG -eq 1 ]; then
        acc_my_run=$((acc_my_run + my_value))
        acc_bpftool_run=$((acc_bpftool_run + bpftool_value))
    fi
done

if [ $ACC_FLAG -eq 1 ]; then
    
    echo "MY RUN AVG, BPFTOOL RUN AVG" >> $output
    echo "$((acc_my_run / num_tests)), $((acc_bpftool_run / num_tests))" >> $output
fi
# unload program
kill -9 $user_pid

echo "Done, output in $output"
