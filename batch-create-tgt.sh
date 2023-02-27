#########################################################################
# File Name: batch-create-tgt.sh
# Author: Yin Congmin
# mail: congmin.yin@intel.com
# Created Time: Fri Feb 24 10:51:26 2023
#########################################################################
#!/bin/bash
i=4
while(( $i<=4 ))
do
    python3 -m control.cli create_bdev -i mytestdevimage -p rbd -b Ceph${i}
		python3 -m control.cli create_subsystem -n nqn.2016-06.io.spdk:cnode${i} -s SPDK0000000000000${i}
		python3 -m control.cli add_namespace -n nqn.2016-06.io.spdk:cnode${i} -b Ceph${i}
		python3 -m control.cli add_host -n nqn.2016-06.io.spdk:cnode${i} -t nqn.2016-06.io.spdk:ssp-cephs
		python3 -m control.cli add_host -n nqn.2016-06.io.spdk:cnode${i} -t '*'
		python3 -m control.cli create_listener -n nqn.2016-06.io.spdk:cnode${i} -s 500${i}
		echo "created target $i"
    let "i++"
done
