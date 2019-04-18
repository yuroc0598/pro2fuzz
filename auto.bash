#!/bin/bash
USR=`logname`
AFL_PATH="./"
PROG_PATH="$AFL_PATH/testcases/openssl"
NTHREAD=$1

# usage

function usage
{
echo "Usage of this testing script:"
echo "---sudo ./auto.bash PACKET_SEQ_Number Number_of_Threads"
echo "---currently only support:"
echo "------Number_of_Threads: int from 1 to N, don't be greedy and leave some cores for others"
}

# check arg format

if [ $# -ne 1 ] || [ $1 -lt 1 ]
then
echo "invalid arguments, check usage below:"
usage
exit -1
fi

# check if the output dir is empty or not


function checkExist
{
path=$1
if [ ! -d "$path" ]
then
mkdir -p "$path" -m 777
else
rm -rf $path/*
fi
}

for (( i=0;i<$NTHREAD;i++ ))
do
in_dir=p1
out_dir=profuzz_out
checkExist "$PROG_PATH/$out_dir"
sub_out_dir=fuzzer"$i"
if [ $i -eq 0 ]
then
$AFL_PATH/experimental/asan_cgroups/limit_memory.sh -u $USR $AFL_PATH/afl-fuzz  -i $PROG_PATH/in/$in_dir -o $PROG_PATH/$out_dir -M $sub_out_dir -m none -t 400 -f $PROG_PATH/input  $PROG_PATH/openssl 
else
$AFL_PATH/experimental/asan_cgroups/limit_memory.sh -u $USR $AFL_PATH/afl-fuzz  -i $PROG_PATH/in/$in_dir -o $PROG_PATH/$out_dir -S $sub_out_dir -m none -t 400 -f $PROG_PATH/input  $PROG_PATH/openssl > /dev/null 2>&1 &
fi
done
