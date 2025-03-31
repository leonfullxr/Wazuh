#!/bin/bash 

logfile="archives.log" 
interval=1 # Interval in seconds 

if [ ! -f "$logfile" ]; 
	then echo "Error: Log file not found!" 
	exit 1 
fi 
echo "[INFO] - Monitoring $logfile for EPS calculation..." 
prev_entries=$(grep -E "^[0-9]{4} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" "$logfile" | wc -l) 

while true; do 
	sleep "$interval" 
	current_entries=$(grep -E "^[0-9]{4} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" "$logfile" | wc -l) 
	new_events=$((current_entries - prev_entries)) 
	
	EPS=$(bc -l <<< "scale=2; $new_events / $interval") 
	echo "[INFO] - $(date '+%Y-%m-%dT%H:%M:%S') - Events: $new_events | EPS: $EPS" 
	
	prev_entries=$current_entries 
done
