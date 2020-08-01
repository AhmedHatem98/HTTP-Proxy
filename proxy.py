# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket
import time
import asyncio
import re


class HttpRequestInfo(object):
    """
    Represents a HTTP request information

    Since you'll need to standardize all requests you get
    as specified by the document, after you parse the
    request from the TCP packet put the information you
    get in this object.

    To send the request to the remote server, call to_http_string
    on this object, convert that string to bytes then send it in
    the socket.

    client_address_info: address of the client;
    the client of the proxy, which sent the HTTP request.

    requested_host: the requested website, the remote website
    we want to visit.

    requested_port: port of the webserver we want to visit.

    requested_path: path of the requested resource, without
    including the website name.

    NOTE: you need to implement to_http_string() for this class.
    """

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        """
        Convert the HTTP request/response
        to a valid HTTP string.
        As the protocol specifies:

        [request_line]\r\n
        [header]\r\n
        [headers..]\r\n
        \r\n

        (just join the already existing fields by \r\n)

        You still need to convert this string
        to byte array before sending it to the socket,
        keeping it as a string in this stage is to ease
        debugging and testing.
        """
        requestLine = self.method + " " + self.requested_path + " HTTP/1.0" + "\r\n"
        headersLines = ""
        for header in self.headers:
            if header[0].lower() == "host":
                if self.requested_port != 80:
                    headersLines += header[0] + ": " + header[1] +":"+ str(self.requested_port) + "\r\n"
                else:
                    headersLines += header[0] + ": " + header[1] + "\r\n"
            else:
                headersLines += header[0] + ": " + header[1] + "\r\n"
        return requestLine + headersLines + "\r\n"

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Path:", self.requested_path)

        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        return "HTTP/1.0 " + str(self.code) + " " + self.message + "\r\n\r\n"

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.

    Leave this as is, feel free to add yours.
    """
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    cacheMemory = []
    server_socket = setup_sockets(proxy_port_number)
    do_socket_logic(server_socket,cacheMemory)

def checkCache(cacheMemory,key):
    for element in cacheMemory:
        requestInfo = element['RequestInfo']
        if(requestInfo.requested_host == key.requested_host and requestInfo.requested_port == key.requested_port and
                requestInfo.requested_path == key.requested_path and requestInfo.method == key.method and requestInfo.headers == key.headers):
            return element['Data']
    return []


async def handle_client(loop, client, addr,cacheMemory):
    print("Connected to client ",addr)
    data = (await loop.sock_recv(client, 48 * 4096))
    print(f"Got [{len(data)}] bytes From Client...")
    parsed = http_request_pipeline(addr, data.decode())
    cacheData = checkCache(cacheMemory,parsed)

    if (type(parsed) == HttpErrorResponse):
        response = parsed.to_byte_array(parsed.to_http_string())
    elif(cacheData):
        print("Found in Cache !")
        response = cacheData
    else:
        d = parsed.to_byte_array(parsed.to_http_string())
        response = serverSend(d, (parsed.requested_host, parsed.requested_port))
        cacheMemory.append({'RequestInfo':parsed ,'Data':response})

    await loop.sock_sendall(client, response)
    client.close()

async def run_proxy(loop, socket_server,cacheMemory):
    while True:
        client, addr = await loop.sock_accept(socket_server)
        loop.create_task(handle_client(loop, client, addr,cacheMemory))


def setup_sockets(proxy_port_number):
    """
    Socket logic MUST NOT be written in the any
    class. Classes know nothing about the sockets.

    But feel free to add your own classes/functions.

    Feel free to delete this function.
    """
    print("Starting HTTP proxy on port:", proxy_port_number)

    # when calling socket.listen() pass a number
    # that's larger than 10 to avoid rejecting
    # connections automatically.

    server_socket = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)
    # Set the address to be reusable, to avoid waiting for a while if the program
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Set the server address
    server_socket.bind(("127.0.0.1", proxy_port_number))

    # Start listening, this makes the socket a "welcome" socket
    # that gives birth to a socket per each connecting client.
    server_socket.listen(20)
    server_socket.setblocking(False)

    print("Waiting for clients...")
    # now try: curl -X GET http://127.0.0.1:11112 (in terminal)
    # and see the connection in the code here.

    return server_socket


def do_socket_logic(server_socket,cacheMemory):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_proxy(loop, server_socket,cacheMemory))





def serverSend(data, address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting To Server ", address, "...")

    # Connect to our HTTP server, make sure the server is already running.
    client_socket.connect(address)
    print("Connected, sending request...")

    # Send an HTTP request to get an image
    client_socket.send(data)
    print("Sent request...")
    #time.sleep(0.7)
    # Receive the reply
    data = client_socket.recv(48 * 4096)
    print(len(data))
    # Extract the HTTP header (request line + headers) and body.
    header, body = data.split(b'\r\n\r\n')
    print(body.decode())
    print("*" * 50)
    print(f"H:[{len(header)}] bytes\nB:[{len(body)}] bytes...\n")
    print(header.decode())
    print("*" * 50)
    client_socket.close()
    return data


def http_request_pipeline(source_addr, http_raw_data):
    """
    HTTP request processing pipeline.

    - Validates the given HTTP request and returns
      an error if an invalid request was given.
    - Parses it
    - Returns a sanitized HttpRequestInfo

    returns:
     HttpRequestInfo if the request was parsed correctly.
     HttpErrorResponse if the request was invalid.

    Please don't remove this function, but feel
    free to change its content
    """
    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)
    if (validity == HttpRequestState.INVALID_INPUT):
        return HttpErrorResponse(400, "Bad Request")
    elif (validity == HttpRequestState.NOT_SUPPORTED):
        return HttpErrorResponse(501, "Not Implemented")
    elif (validity == HttpRequestState.GOOD):
        parsed = parse_http_request(source_addr, http_raw_data)
        sanitize_http_request(parsed)
        print("**** Required format request to be sent ****")
        print(parsed.to_http_string())
        return parsed
    # Return error if needed, then:
    # parse_http_request()
    # sanitize_http_request(
    # Validate, sanitize, return Http object.
    # print("*" * 50)
    # print("[http_request_pipeline] Implement me!")
    # print("*" * 50)
    return None


def parse_http_request(source_addr, http_raw_data):
    """
    This function parses a "valid" HTTP request into an HttpRequestInfo
    object.
    """
    http_raw_data = http_raw_data[0:-4]
    lines = http_raw_data.split("\r\n")
    lines = [k for k in lines if k != '']
    tokens = lines[0].split(" ")
    tokens = [k for k in tokens if k != '']
    method = tokens[0]
    headers = []
    host, path, port = parseUrl(tokens[1])
    version = tokens[2]
    if (len(lines) == 1):
        ret = HttpRequestInfo(source_addr, method.strip(), host.strip(), int(port), path.strip(), headers)
    else:
        for i in range(1, len(lines)):
            parsed = parseHeader(lines[i])
            if (len(parsed) > 2):
                host = parsed[1]
                if(parsed[2].endswith("/")):
                    path = parsed[2] + path[1:]
                else:
                    path = parsed[2] + path[0:]
                port = parsed[3]
            headers.append([parsed[0].strip(), parsed[1].strip()])
        ret = HttpRequestInfo(source_addr, method.strip(), host.strip(), int(port), path.strip(), headers)
    return ret


def check_http_request_validity(http_raw_data) -> HttpRequestState:
    """
    Checks if an HTTP request is valid

    returns:
    One of values in HttpRequestState
    """

    if (len(http_raw_data) == 0):
        print("Empty request")
        return HttpRequestState.INVALID_INPUT
    if (not http_raw_data.endswith("\r\n")):
        print("Must end with \\r\\n")
        return HttpRequestState.INVALID_INPUT
    http_raw_data = http_raw_data[0:-4]
    lines = http_raw_data.split("\r\n")
    lines = [k for k in lines if k != '']
    print(lines)
    if (len(lines) == 0):
        print("Empty request")
        return HttpRequestState.INVALID_INPUT
    tokens = lines[0].split(" ")
    tokens = [k for k in tokens if k != '']

    path = tokens[1]
    if (len(lines) == 1):
        if (path.startswith("/")):
            print("Missing Host")
            return HttpRequestState.INVALID_INPUT
    else:
        if (path.startswith("/")):
            if (checkHost(lines[1:]) == 0):
                return HttpRequestState.INVALID_INPUT
        else:
            if (validateHeaders(lines[1:]) == 0):
                return HttpRequestState.INVALID_INPUT

    if (len(tokens) < 3):
        print("Invalid Http: Missing arguments")
        return HttpRequestState.INVALID_INPUT
    version = tokens[2].lower()
    if (not version.startswith("http/1")):
        print("Invalid http version argument")
        return HttpRequestState.INVALID_INPUT
    method = tokens[0]
    methodChecked = checkMethod(method)
    if (methodChecked == 0):
        print("Not implemented")
        return HttpRequestState.NOT_SUPPORTED
    elif (methodChecked == -1):
        print("Bad Request")
        return HttpRequestState.INVALID_INPUT
    else:
        return HttpRequestState.GOOD


def parseHeader(header):
    index = header.find(":")
    title = header[0:index]
    value = header[index+1:]
    if (title.strip().lower() == "host"):
        host, path, port = parseUrl(value)
        return (title, host, path, port)
    else:
        return (title, value)


def parseUrl(url):
    url = url.strip()
    temp = url[:]
    if (url.lower().startswith("http://")):
        temp = url[7:]
    elif (url.lower().startswith("https://")):
        temp = url[8:]
    if (":" in temp):
        index = temp.find(":")
        host = temp[0:index]
        if ("/" in temp):
            indx = temp.find("/")
            port = temp[index + 1:indx]
            path = temp[indx:]
        else:
            port = temp[index + 1:]
            path = "/"
    else:
        if ("/" in temp):
            indx = temp.find("/")
            host = temp[0:indx]
            port = "80"
            path = temp[indx:]
        else:
            host = temp[0:]
            port = "80"
            path = "/"
    return host, path, port

def validateHeaders(lines):
    for line in lines:
        if ":" not in line:
            print("Colon Required")
            return 0
    return 1
def checkHost(lines):
    headers = []
    for line in lines:
        if ":" in line:
            temp = line.split(":")
            headers.append((temp[0].strip(), temp[1].strip()))
        else:
            print("Colon Required")
            return 0
    for header in headers:
        if header[0].lower() == "host":
            if header[1].lower().startswith("/"):
                print("Required a host not path")
                return 0
            return 1
    print("Required Host")
    return 0


def checkMethod(method):
    if method.lower() == "get":
        return 1
    elif method.lower() == "head" or method.lower() == "post" or method.lower() == "put" \
            or method.lower() == "delete" or method.lower() == "connect" or method.lower() == "options" \
            or method.lower() == "trace" or method.lower() == "patch":
        return 0
    else:
        return -1

def inHeaders(headers,key):
    for header in headers:
        if header[0].lower() == key:
            return 1
    return 0
def sanitize_http_request(request_info: HttpRequestInfo):
    """
    Puts an HTTP request on the sanitized (standard) form
    by modifying the input request_info object.

    for example, expand a full URL to relative path + Host header.

    returns:
    nothing, but modifies the input object
    """
    if inHeaders(request_info.headers,"host") ==0:
        request_info.headers.insert(0, ["Host", request_info.requested_host])




def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.

        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)  # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*

    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.

    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = int(get_arg(1, 18888))
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()
