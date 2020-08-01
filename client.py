
import socket
import asyncio
import time

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting...")

# Connect to our HTTP server, make sure the server is already running.
client_socket.connect(("127.0.0.1", 18888))
print("Connected, sending request...")

# Send an HTTP request to get an image
#client_socket.send(b"GET / HTTP/1.0\r\nHost:www.google.com\r\n\r\n")
time.sleep(0.7)
st = time.time()
client_socket.send(b"GET apache.org:80 HTTP/1.0\r\n\r\n")

print("Sent request...")

# Wait for the socket to process the request, note that
# in real life you don't need to put any code to wait.
# but our case is an exception because we're calling another
# process in the same OS so things happen way fast.

# Receive the reply
data = client_socket.recv(28 * 4096)
en = time.time()
# Extract the HTTP header (request line + headers) and body.
header, body = data.split(b'\r\n\r\n')
print(data.decode())
print("*" * 50)
print(f"H:[{len(header)}] bytes\nB:[{len(body)}] bytes...\n")
print(header.decode())
#print(body.decode())
print("*" * 50)
print(en-st)

client_socket.close()
