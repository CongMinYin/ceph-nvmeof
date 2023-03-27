#########################################################################
# File Name: disover.sh
# Author: Yin Congmin
# mail: congmin.yin@intel.com
# Created Time: 2023年03月20日 星期一 14时06分24秒
#########################################################################
#!/bin/bash
timer_start=`date "+%Y-%m-%d %H:%M:%S"`
loop=1
while(( $loop<=1000 ))
do
	nohup nvme discover -t tcp -a 10.239.241.67 -s 1234 1>&2 2>/dev/null &
	#nohup nvme discover -t tcp -a 10.239.241.67 -s 1234 &
	#echo $loop
    let "loop++"
done
timer_end=`date "+%Y-%m-%d %H:%M:%S"`
start_seconds=$(date --date="$timer_start" +%s);
end_seconds=$(date --date="$timer_end" +%s);
echo "start time: $timer_start"
echo "end time: $timer_end"
echo "run time"$((end_seconds-start_seconds)) "s"

