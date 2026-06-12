#!/bin/bash

echo "===PhishPhaser Automated Listener Active ==="
echo "Monitoring watch_folder/ for incoming threats..."

#run an infinite loop to simulate a background daemon
while true; do
    #check if there are any files inside the watch_folder
    if [ "$(ls -A watch_folder)" ]; then
        echo "[!] New suspicious email detected in pipleine!"

        #loop through every file found in watch_folder
        for file in watch_folder/*; do
            echo "[*] Ingesting: $file"

            #fire python engine dynamically
            python3 phish_phaser.py "$file"

            #clean up move the processed file out so it doesnt loop forever
            rm "$file"
            echo "[+] Analysis complete. File cleared from queue."
            echo "-----------------------------------------------"
            
        done
    fi

    #wait 3 seconds before scanning permiter again
    sleep 3
done