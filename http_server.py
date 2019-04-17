import socket
import threading
from colorama import Back
from loguru import logger as LOG


def server(host, port, backlog=100):
    sock_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with sock_srv:
        sock_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_srv.bind((host, port))
        sock_srv.listen(backlog)
        LOG.info('Server listening at http://{}:{}'.format(host, port))
        while True:
            sock_cli, addr_cli = sock_srv.accept()
            t = threading.Thread(target=handler, args=(sock_cli, addr_cli))
            t.start()


def read_until(sock, sep, buffer=b''):
    while True:
        data = sock.recv(4096)
        if not data:
            break
        buffer += data
        if sep in buffer:
            break
    parts = buffer.split(sep, maxsplit=1)
    if len(parts) == 2:
        result, extra = parts
    else:
        result, extra = parts[0], b''
    return result, extra


def read_exact(sock, size, buffer=b''):
    remain_size = size - len(buffer)
    while remain_size > 0:
        data = sock.recv(remain_size)
        if not data:
            break
        buffer += data
        remain_size = size - len(buffer)
    return buffer


class Request:
    def __init__(self, method, path, version, headers, body):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.body = body

    def __repr__(self):
        return '<Request {} {}>'.format(self.method, self.path)

    @staticmethod
    def parse_header(header_data):
        """
        https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5
        Request       = Request-Line              ; Section 5.1
                        *(( general-header        ; Section 4.5
                         | request-header         ; Section 5.3
                         | entity-header ) CRLF)  ; Section 7.1
                        CRLF
                        [ message-body ]          ; Section 4.3
        Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
        """
        lines = header_data.decode().splitlines()
        method, path, version = lines[0].split(' ')
        headers = {}
        for line in lines[1:]:
            name, value = line.split(':', maxsplit=1)
            headers[name.strip().lower()] = value.strip()
        return method, path, version, headers


class Response:
    def __init__(self, status=200, status_text='OK', version='HTTP/1.1', headers=None, body=None):
        self.status = status
        self.status_text = status_text
        self.version = version
        self.headers = headers or {}
        self.body = body or b''
        self.headers['content-length'] = str(len(self.body))

    def __repr__(self):
        return '<Response {} {}>'.format(self.status, self.status_text)

    def __bytes__(self):
        """
        https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html
        Response      = Status-Line               ; Section 6.1
                        *(( general-header        ; Section 4.5
                         | response-header        ; Section 6.2
                         | entity-header ) CRLF)  ; Section 7.1
                        CRLF
                        [ message-body ]          ; Section 7.2
        Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
        """
        status_line = '{} {} {} \r\n'.format(self.version, self.status, self.status_text)
        header = ''
        for name, value in self.headers.items():
            header += '{}: {}\r\n'.format(name, value)
        return (status_line + header + '\r\n').encode() + self.body


def handler(sock_cli, addr_cli):
    with sock_cli:
        LOG.info('Connected by {}:{}'.format(*addr_cli))
        header_data, extra = read_until(sock_cli, b'\r\n\r\n')
        print(Back.RED + header_data.decode() + Back.RESET)  # request header
        method, path, version, headers = Request.parse_header(header_data)
        content_length = int(headers.get('content-length') or 0)
        if content_length <= 0:
            body = b''
        else:
            body = read_exact(sock_cli, size=content_length, buffer=extra)
            print(Back.RED + body.decode() + Back.RESET)  # request body
        request = Request(method, path, version, headers, body)
        response = http_handler(request)
        response_data = bytes(response)
        print(Back.RED + response_data.decode() + Back.RESET)  # response
        sock_cli.sendall(response_data)
    LOG.info('Connection closed {}:{}'.format(*addr_cli))


def http_handler(request):
    LOG.info(request)
    response = Response(body=b'Hello world!!')
    LOG.info(response)
    return response


if __name__ == "__main__":
    server('127.0.0.1', 5000)
