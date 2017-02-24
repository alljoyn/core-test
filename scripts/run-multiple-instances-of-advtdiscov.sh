# Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
# Project (AJOSP) Contributors and others.
# 
# SPDX-License-Identifier: Apache-2.0
# 
# All rights reserved. This program and the accompanying materials are
# made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
# Alliance. All rights reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all
# copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
# Warn on using uninitialized variables
set -o nounset

readonly my_dev_null="/dev/null"

# Based on guidelines at http://www.freebsd.org/cgi/man.cgi?query=sysexits
readonly EX_OK=0
readonly EX_USAGE=64
readonly EX_DATAERR=65
readonly EX_NOINPUT=66

display_usage () {
    printf "Usage:$(basename $0)\n"
    printf "\t-d <path-to-alljoyn-dist-folder>\n"
    printf "\t-t <path-to-advtdiscov-test-program>\n"
    printf "\t-a <number-of-advertisers>\n"
    printf "\t-c <number-of-consumers>\n"
    printf "\t   (sum total of advertisers and consumers can be a max of 100)\n"
    printf "\t-u <number-of-names-each-consumer-should-discover>\n"
    printf "\t-m <time-for-which-an-instance-should-run-in-seconds>\n"
    printf "\t-n <name-prefix-that-is-advertised-and-discovered>\n"
    printf "\t-r Randomize the time for which advertiser should run\n"
    printf "\t-s Start stand-alone routing node\n"
    printf "\t-o <directory-in-which-log-files-are-to-be-stored>\n"

    exit $EX_USAGE
}

location_of_alljoyn_dist="" # option -d
location_of_test_binary="" # option -t

num_advertisers=0 # option -a
num_consumers=0 # option -c
num_names_each_consumer_should_discover="" # option -u

name_prefix_to_advertise_discover="test.dreamworks.howtotrainyourdragon" # option -n

# TTL of name = duration for which name is advertised / discovered (val in s)
ttl_of_name=10 # option -m
random_ttl_enabled=false # option -r

configured_to_use_standalone_router_node=false # option -s

log_file_directory="" # option -o

# Read the command-line options
while getopts "d:t:a:c:u:m:n:o:rsh" option;
do
    case $option in
    d)
        location_of_alljoyn_dist="$OPTARG"
        ;;
    t)
        location_of_test_binary="$OPTARG"
        ;;
    a)
        num_advertisers=$OPTARG
        ;;
    c)
        num_consumers=$OPTARG
        ;;
    u)
        num_names_each_consumer_should_discover=$OPTARG
        ;;
    m)
        ttl_of_name=$OPTARG
        ;;
    n)
        name_prefix_to_advertise_discover="$OPTARG"
        ;;
    o)
        log_file_directory="$OPTARG"
        ;;
    r)
        random_ttl_enabled=true
        ;;
    s)
        configured_to_use_standalone_router_node=true
        ;;
    h)
        display_usage
        ;;
    \?)
        display_usage
    esac
done

readonly location_of_alljoyn_dist
readonly location_of_test_binary
readonly log_file_directory

# If any of the above locations were not specified via command-line, they
# would be empty and the script cannot proceed.
if test -z "$location_of_alljoyn_dist" -o -z "$location_of_test_binary" -o -z "$log_file_directory"
then
    printf "ERROR: One of the following options is unspecified. Cannot continue.\n"
    printf "\ta. Location of AllJoyn distribution directory (-d option): $location_of_alljoyn_dist\n"
    printf "\tb. Path to advtdiscov test program (-t option): $location_of_test_binary\n"
    printf "\tc. Location of directory to store logs (-o option): $log_file_directory\n"
    exit $EX_NOINPUT
fi

readonly num_advertisers
readonly num_consumers
# If both the number of advertisers and consumers is set to zero
# then, there is no need to proceed.
if test 0 -eq $num_advertisers -a 0 -eq $num_consumers
then
    printf "ERROR: Nothing to do (no. of advertisers = $num_advertisers and no. of consumers = $num_consumers).\n"
    exit $EX_NOINPUT
fi

if test -z $num_names_each_consumer_should_discover
then
    # If the number of names to discover is not specified, then discover
    # all the names Advertised. Each advertiser advertises one name.
    num_names_each_consumer_should_discover=$num_advertisers
fi
readonly num_names_each_consumer_should_discover

readonly ttl_of_name
readonly random_ttl_enabled

readonly name_prefix_to_advertise_discover

readonly configured_to_use_standalone_router_node

# If random ttl is enabled then, ttl is generated between min and max
# If random ttl is disabled then, ttl is computed as average of min and max
if $random_ttl_enabled
then
    min_ttl_of_name=0
else
    min_ttl_of_name=$(( ttl_of_name * 1000 )) # Conversion to milliseconds
fi

readonly min_ttl_of_name
readonly max_ttl_of_name=$(( ttl_of_name * 1000 ))

readonly random_seed=1984 # For repeatable results

# Sanity checks
if test ! -d $location_of_alljoyn_dist
then
    printf "ERROR: Invalid AllJoyn distribution directory (at: $location_of_alljoyn_dist).\n"
    exit $EX_NOINPUT
fi

if test ! -f "$location_of_alljoyn_dist/cpp/lib/liballjoyn.so"
then
    printf "ERROR: Unable to find liballjoyn.so (at: $location_of_alljoyn_dist/cpp/lib).\n"
    exit $EX_NOINPUT
fi

# Set LD_LIBRARY_PATH to allow the binaries find the needed libs (only on Linux)
if test "Linux" = $(uname -s)
then
    export LD_LIBRARY_PATH="$location_of_alljoyn_dist/cpp/lib"
fi

if test ! -f $location_of_test_binary
then
    printf "ERROR: Unable to find test binary at: $location_of_test_binary.\n"
    exit $EX_NOINPUT
fi

readonly max_num_advertisers_consumers=100
if test $max_num_advertisers_consumers -lt $(( num_advertisers + num_consumers ))
then
    printf "ERROR: Too many processes (advertisers: $num_advertisers, consumers: $num_consumers) to launch (sum of advertisers and consumers can be $max_num_advertisers_consumers at most).\n"
    exit $EX_DATAERR
fi

if $configured_to_use_standalone_router_node
then
    if test ! -f "$location_of_alljoyn_dist/cpp/bin/alljoyn-daemon"
    then
        printf "ERROR: Unable to find alljoyn-daemon at: $location_of_alljoyn_dist/cpp/bin/alljoyn-daemon.\n"
        exit $EX_NOINPUT
    fi
fi

# Just in case, enable coredumps
ulimit -c unlimited

# Start the stand-alone routing node if applicable
if $configured_to_use_standalone_router_node
then
    mkdir -p $log_file_directory && cd $log_file_directory && "$location_of_alljoyn_dist/cpp/bin/alljoyn-daemon" --print-pid --verbosity=7 1>$log_file_directory/router-$name_prefix_to_advertise_discover.log 2>&1 &
    readonly pid_of_router_node=$!
    printf "Started the routing node (pid: $pid_of_router_node, log: $log_file_directory/router-$name_prefix_to_advertise_discover.log).\n"

    # Don't launch consumers too soon after launching routing node
    sleep 1
fi

# Start Consumers before starting Advertisers
# Consumer (discovering side) attempts to find a name and waits till it is lost
consumer_pids_list=""
readonly consumer_mode="$location_of_test_binary -m discover -n $name_prefix_to_advertise_discover -cn $num_names_each_consumer_should_discover"

random_offset=$random_seed
loop_counter=0
while test $num_consumers -gt $loop_counter
do
    if $random_ttl_enabled
    then
        random_offset=$(awk "BEGIN { srand($random_offset); print int(rand() * ($max_ttl_of_name - $min_ttl_of_name)) }")
        name_ttl=$(( min_ttl_of_name + random_offset ))
    else
        name_ttl=$(( min_ttl_of_name + max_ttl_of_name ))
        name_ttl=$(( name_ttl / 2 ))
    fi

    # Start each consumer in its own directory so that any core files
    # generated don't clobber one another
    mkdir -p $log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter && cd $log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter && $consumer_mode -ttl $name_ttl 1>consumer.log 2>&1 &
    pid_of_consumer=$!

    printf "$((loop_counter + 1)) of $num_consumers: Launched Consumer (pid: $pid_of_consumer log: $log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter/consumer.log).\n"

    consumer_pids_list="$consumer_pids_list $pid_of_consumer"
    loop_counter=$((loop_counter + 1))

    if test 0 -eq $(( loop_counter % 10 ))
    then
        sleep 1 # Be realistic. Have a gap between launch of consumers.
    fi
done
if test 0 -lt $num_consumers
then
    printf "Done launching all consumers.\n"
fi
readonly consumer_pids_list

# Be realistic. Don't launch advertisers too soon after launching consumers
sleep 1

# Start Advertisers
advertiser_pids_list=""
readonly advertiser_mode="$location_of_test_binary -m advertise -linger -n $name_prefix_to_advertise_discover"

random_offset=$random_seed
loop_counter=0
while test $num_advertisers -gt $loop_counter
do
    if $random_ttl_enabled
    then
        random_offset=$(awk "BEGIN { srand($random_offset); print int(rand() * ($max_ttl_of_name - $min_ttl_of_name)) }")
        name_ttl=$(( min_ttl_of_name + random_offset ))
    else
        name_ttl=$(( min_ttl_of_name + max_ttl_of_name ))
        name_ttl=$(( name_ttl / 2 ))
    fi

    # Start each advertiser in its own directory so that any core files
    # generated don't clobber one another
    mkdir -p $log_file_directory/advt-$name_prefix_to_advertise_discover-$loop_counter && cd $log_file_directory/advt-$name_prefix_to_advertise_discover-$loop_counter && $advertiser_mode -ttl $name_ttl 1>advertiser.log 2>&1 &
    pid_of_advertiser=$!

    printf "$((loop_counter + 1)) of $num_advertisers: Launched Advertiser (pid: $pid_of_advertiser log: advt-$name_prefix_to_advertise_discover-$loop_counter/advertiser.log duration: $name_ttl ms).\n"

    advertiser_pids_list="$advertiser_pids_list $pid_of_advertiser"
    loop_counter=$((loop_counter + 1))

    if test 0 -eq $(( loop_counter % 10 ))
    then
        sleep 1 # Be realistic. Have a gap between launch of advertisers.
    fi
done
if test 0 -lt $num_advertisers
then
    printf "Done launching all advertisers.\n"
fi
readonly advertiser_pids_list

# Wait for advertisers to complete (poll their status)
while true
do
    # Recompute the number of advertisers still running
    num_advertisers_still_running=0
    for pid in $advertiser_pids_list
    do
        if kill -0 $pid 1>$my_dev_null 2>&1
        then
           num_advertisers_still_running=$(( num_advertisers_still_running + 1 ))
        fi
    done

    if test 0 -lt $num_advertisers_still_running
    then
        printf "$(date): $num_advertisers_still_running of $num_advertisers advertisers still running.\n"
    else
        # All Advertisers have exited and so polling can be stopped.
        printf "All advertisers have exited.\n"
        break
    fi

    sleep 1
done

printf "Checking for any core files generated by advertisers...\n"
loop_counter=0
while test $num_advertisers -gt $loop_counter
do
    if test -f "$log_file_directory/advt-$name_prefix_to_advertise_discover-$loop_counter/core"
    then
        printf "Found core file ($log_file_directory/advt-$name_prefix_to_advertise_discover-$loop_counter/core).\n"
    fi

    loop_counter=$(( loop_counter + 1 ))
done
printf "Done.\n"

# Wait for Consumers to exit
# In an ideal scenario, Consumers would exit soon after Advertisers have
# exited. However, to be on the safe-side, have a timeout of 15 seconds
# after which any remaining consumers can be forcibly terminated.
# The time to wait is computed as (15 * number_of_consumers)
time_slept=0
while true
do
    # Recompute the number of consumers still running
    num_consumers_still_running=0
    loop_counter=0
    for pid in $consumer_pids_list
    do
        if kill -0 $pid 1>$my_dev_null 2>&1
        then
            num_consumers_still_running=$(( num_consumers_still_running + 1 ))
            printf "\tConsumer $loop_counter says: $(tail -n 1 $log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter/consumer.log)\n"
        fi

        loop_counter=$(( loop_counter + 1 ))
    done

    if test 0 -lt $num_consumers_still_running
    then
        printf "$(date): $num_consumers_still_running of $num_consumers consumers still running.\n"

        if test $(( 15 * $num_consumers )) -eq $time_slept
        then
            # Have waited enough, so kill any remaining consumers
            printf "Waited $(( 15 * $num_consumers ))s for all Consumers to exit.\n"
            printf "Foribly stopping the remaining $num_consumers_still_running of $num_consumers consumers.\n"
            for pid in $consumer_pids_list
            do
                if kill -0 $pid 1>$my_dev_null 2>&1
                then
                    kill $pid # Send SIGTERM

                    sleep 2
                    # If the process has deadlocked or took too long to stop,
                    # log it
                    if kill -0 $pid 1>$my_dev_null 2>&1
                    then
                        printf "WARN: Consumer(pid: $pid) is taking longer than usual to stop. Skipping...\n"
                    fi
                fi
            done
            printf "Done.\n"

            break
        fi
    else
        # All consumers have exited and so polling can be stopped
        printf "All consumers have exited.\n"
        break
    fi

    sleep 1
    time_slept=$(( time_slept + 1 ))
done

printf "Checking for any core files generated by consumers...\n"
loop_counter=0
while test $num_consumers -gt $loop_counter
do
    if test -f "$log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter/core"
    then
        printf "Found core file ($log_file_directory/cons-$name_prefix_to_advertise_discover-$loop_counter/core).\n"
    fi

    loop_counter=$(( loop_counter + 1 ))
done
printf "Done.\n"

# Stop stand-alone routing node, if applicable
if $configured_to_use_standalone_router_node
then
    # Routing node should be running even now
    if ! kill -0 $pid_of_router_node 1>$my_dev_null 2>&1
    then
        printf "WARN: Routing node (pid: $pid_of_router_node) is no longer running.\n"
    else
        printf "Stopping stand-alone routing node... (will wait for $(( num_advertisers + num_consumers )) seconds after sending kill signal, time now is $(date))\n"
        kill $pid_of_router_node # Send SIGTERM to alljoyn-daemon

        # How long to wait after sending the kill signal?
        # The best thing is to wait based on the number of advertisers connected
        # to the routing node (which increase the cleanup-related effort)
        sleep $(( num_advertisers + num_consumers ))
        # If the routing node process has deadlocked or took too long to stop,
        # log it
        if kill -0 $pid_of_router_node 1>$my_dev_null 2>&1
        then
            printf "WARN: Routing node(pid: $pid_of_router_node) is taking longer than usual to stop after sending kill signal. Skipping...\n"
        else
            printf "Done (routing node exited).\n"
        fi
    fi
fi

# If there is a core file in $log_file_directory, then it belongs
# to alljoyn-daemon
if test -f "$log_file_directory/core"
then
    printf "Found core file ($log_file_directory/core) that corresponds to routing node.\n"
fi

exit $EX_OK