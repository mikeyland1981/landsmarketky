import argparse
import socket
import ssl
import sys

def main():
    parser = argparse.ArgumentParser(description='ICAP client with SSL/TLS support')
    parser.add_argument('--server', required=True, help='ICAP server address (host[:port])')
    parser.add_argument('--file', required=True, help='File to scan')
    args = parser.parse_args()

    # Parse server address
    if ':' in args.server:
        host, port = args.server.split(':', 1)
        port = int(port)
    else:
        host = args.server
        port = 1344  # Default ICAP port

    # Read file content
    try:
        with open(args.file, 'rb') as f:
            file_content = f.read()
    except IOError as e:
        print("Error reading file:", e)
        sys.exit(1)

    # Build encapsulated HTTP request
    http_headers = "POST /upload HTTP/1.1\r\n"
    http_headers += "Host: example.com\r\n"
    http_headers += "Content-Length: %d\r\n" % len(file_content)
    http_headers += "\r\n"
    encapsulated_data = http_headers + file_content

    # Build ICAP request
    service_path = 'reqmod'
    if port != 1344:
        uri = 'icap://%s:%d/%s' % (host, port, service_path)
    else:
        uri = 'icap://%s/%s' % (host, service_path)

    host_header = '%s:%d' % (host, port) if port != 1344 else host
    encapsulated_header = "req-hdr=0, req-body=%d" % len(http_headers)

    icap_request = [
        "REQMOD %s ICAP/1.0" % uri,
        "Host: %s" % host_header,
        "Encapsulated: %s" % encapsulated_header,
        "Transfer-Encoding: chunked",
        "",
        ""
    ]
    icap_headers = "\r\n".join(icap_request)

    # Build chunked body
    chunk_size = len(encapsulated_data)
    chunked_body = "%x\r\n%s\r\n0\r\n\r\n" % (chunk_size, encapsulated_data)

    try:
        # Establish SSL connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLSv1, cert_reqs=ssl.CERT_NONE)

        # Send ICAP request
        ssl_sock.sendall(icap_headers + chunked_body)

        # Receive response
        response = []
        while True:
            data = ssl_sock.recv(4096)
            if not data:
                break
            response.append(data)
        full_response = ''.join(response)

    except Exception as e:
        print("Connection error:", e)
        sys.exit(1)
    finally:
        ssl_sock.close()

    print("ICAP Response:")
    print(full_response)

if __name__ == '__main__':
    main()