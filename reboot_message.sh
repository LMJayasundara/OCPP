#!/bin/sh
echo "Last reboot time: $(date)" > /etc/motd

# Check firmware update is available
DIR="/home/ubuntu/Firmware"
if [ -d "$DIR" ]; then
	timestamp="$(date +%s)"
	mv /home/ubuntu/ID001 /home/ubuntu/Backup_$timestamp

	if [ -d "/home/ubuntu/Backup_$timestamp" ]; then
		mv /home/ubuntu/Firmware /home/ubuntu/ID001

		if [ -f "/home/ubuntu/ID001/package.json" ]; then
			cd /home/ubuntu/ID001 && npm install
		fi
	fi
	echo "New Firmware Updated!" > /etc/motd
fi
