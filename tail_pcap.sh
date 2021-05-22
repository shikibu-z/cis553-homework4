#!/bin/bash

if [ "$#" -lt 1 ]; then
	echo "Usage: ./tail_pcap.sh <path_to_pcap_file>"
	exit 1
fi

tail -c +1 -f ${1} | tcpdump -lne --immediate-mode -r -

