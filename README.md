# OCPP
EV Charger Protocol

1. Run ``` node gen.js ``` for generate certificates.

2. Run node server using ``` node server.js ```.

3. Create client's certificates using Postman
   Check for the API documentation: ``` https://documenter.getpostman.com/view/21583239/2s83zdx74z ```

4. Copy certificates to dir which are required (Refer client's requiremets.txt).

5. Run each clients using ``` cd {client_dir} && node client.js ```

6. For firmware update:

    1. Copy ``` reboot_message.sh ``` file to root dir and give authorize to execute using ``` sudo chmod +x reboot_message.sh && sudo chmod 777 reboot_message.sh ```

    2. Enter cron using sudo:
        ``` sudo crontab -e ```

    3. Add a command to run upon start up, in this case a script:

        ``` @reboot sh /{path to .sh file}/reboot_message.sh ```
    
    4. Save
