import socket
import threading
import hashlib
import base64
import struct
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
    if len(parts) == 2 or 1:
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
    def __init__(self, method, path, version, headers, params, body, sock_cli=None, addr_cli=None):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.params = params
        self.body = body
        self.sock_cli = sock_cli
        self.addr_cli = addr_cli

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
        path, params = Request.parse_params(path)
        return method, path, version, headers, params

    @staticmethod
    def parse_params(path):
        """
        /chat?user=xxx
        """
        if '?' not in path:
            return path, {}
        params = {}
        path, params_data = path.split('?', maxsplit=1)
        for kv_data in params_data.split('&'):
            k, v = kv_data.split('=', maxsplit=1)
            params[k] = v
        return path, params


class Response:
    def __init__(self, status=200, status_text='OK', version='HTTP/1.1', headers=None, body=None, keepalive=False):
        self.status = status
        self.status_text = status_text
        self.version = version
        self.headers = headers or {}
        self.body = body or b''
        self.headers['content-length'] = str(len(self.body))
        self.keepalive = keepalive

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
    try:
        LOG.info('Connected by {}:{}'.format(*addr_cli))
        header_data, extra = read_until(sock_cli, b'\r\n\r\n')
        if not header_data:
            return
        print(Back.RED + header_data.decode() + Back.RESET)  # request header
        method, path, version, headers, params = Request.parse_header(header_data)
        content_length = int(headers.get('content-length') or 0)
        if content_length <= 0:
            body = b''
        else:
            body = read_exact(sock_cli, size=content_length, buffer=extra)
            print(Back.RED + body.decode() + Back.RESET)  # request body
        request = Request(method, path, version, headers, params, body, sock_cli, addr_cli)
        response = http_handler(request)
        response_data = bytes(response)
        print(Back.RED + response_data.decode() + Back.RESET)  # response
        sock_cli.sendall(response_data)
    finally:
        if not response.keepalive:
            sock_cli.close()
            LOG.info('Connection closed {}:{}'.format(*addr_cli))


def http_handler(request):
    LOG.info(request)
    if request.path == '/':
        response = http_static_handler(request)
    elif request.path == '/chat':
        response = http_websocket_handler(request)
    else:
        response = Response(status=404, status_text='Not Found', body=b'404 Not Found')
    LOG.info(response)
    return response


def http_static_handler(request):
    with open('index.html', 'rb') as f:
        body = f.read()
    headers = {'content-type': 'text/html;charset=utf-8'}
    response = Response(headers=headers, body=body)
    return response


def compute_websocket_accept(key):
    m = hashlib.sha1()
    m.update((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode())
    accept = base64.b64encode(m.digest()).decode()
    return accept


def http_websocket_handler(request):
    key = request.headers.get('sec-websocket-key')
    user = request.params.get('user')
    if not key or not user:
        return Response(status=400, status_text='BadRequest', body=b'400 BadRequest')
    accept = compute_websocket_accept(key)
    headers = {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Accept': accept,
    }
    t = threading.Thread(target=websocket_handler, args=(user, request.sock_cli))
    t.start()
    return Response(status=101, status_text='Switching Protocols', headers=headers, keepalive=True)


class MessageQueue:

    def __init__(self):
        self.consumers = {}

    def publish(self, producer, message):
        for consumer, callback in self.consumers.items():
            callback(producer, message)

    def subscribe(self, consumer, callback):
        self.consumers[consumer] = callback

    def unsubscribe(self, consumer):
        self.consumers.pop(consumer, None)


MQ = MessageQueue()


def read_frame(sock):
    """
    https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#Exchanging_data_frames
    Frame format:
         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-------+-+-------------+-------------------------------+
        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        | |1|2|3|       |K|             |                               |
        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        |     Extended payload length continued, if payload len == 127  |
        + - - - - - - - - - - - - - - - +-------------------------------+
        |                               |Masking-key, if MASK set to 1  |
        +-------------------------------+-------------------------------+
        | Masking-key (continued)       |          Payload Data         |
        +-------------------------------- - - - - - - - - - - - - - - - +
        :                     Payload Data continued ...                :
        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        |                     Payload Data continued ...                |
        +---------------------------------------------------------------+
    1. Read bits 9-15 (inclusive) and interpret that as an unsigned integer.
       If it's 125 or less, then that's the length; you're done.
       If it's 126, go to step 2. If it's 127, go to step 3.
    2. Read the next 16 bits and interpret those as an unsigned integer. You're done.
    3. Read the next 64 bits and interpret those as an unsigned integer
       (The most significant bit MUST be 0). You're done.

    FIN=0: continuation frame
    FIN=1: complete frame

    opcode=0: continuation frame
    opcode=1: text
    opcode=2: binary

    MASK=1: client -> server
    MASK=0: server -> client
    """
    buffer = read_exact(sock, 2)
    if not buffer:
        return 0, 0, b''
    fin = buffer[0] >> 7
    opcode = buffer[0] & 0b00001111
    mask = buffer[1] >> 7
    number = buffer[1] & 0b01111111
    if number == 126:
        buffer = read_exact(sock, 2)
        length = struct.unpack('>H', buffer)  # unsigned short, 2 bytes
    elif number == 127:
        buffer = read_exact(sock, 8)
        length = struct.unpack('>Q', buffer)  # unsigned long long, 8 bytes
    else:
        length = number
    if mask:
        mark_key = read_exact(sock, 4)
    payload = read_exact(sock, length)
    if mask:
        payload = bytes(x ^ mark_key[i % 4] for i, x in enumerate(payload))
    return fin, opcode, payload


def send_frame(sock, payload):
    assert len(payload) <= 125, 'not support too large payload'
    buffer = bytes([0b10000001, len(payload)]) + payload
    sock.sendall(buffer)


def websocket_handler(user, sock_cli):

    def callback(producer, message):
        LOG.info('{} -> {}: {}'.format(producer, user, message))
        payload = '{}> {}'.format(producer, message).encode()
        send_frame(sock_cli, payload)

    MQ.subscribe(user, callback)
    LOG.info('Websocket connected by {}'.format(user))

    try:
        while True:
            fin, opcode, payload = read_frame(sock_cli)
            if not payload:
                break
            print(Back.MAGENTA + '{}> fin={} opcode={} {}'.format(user, fin, opcode, payload) + Back.RESET)
            if opcode == 1:
                MQ.publish(user, payload.decode())
    finally:
        MQ.unsubscribe(user)
        sock_cli.close()
        LOG.info('Websocket closed by {}'.format(user))


if __name__ == "__main__":
    server('127.0.0.1', 5000)
