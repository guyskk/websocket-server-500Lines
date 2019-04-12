import socket
import threading
from loguru import logger as LOG


def server(host, port, backlog=100):
    sock_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with sock_srv:
        sock_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_srv.bind((host, port))
        sock_srv.listen(backlog)
        LOG.info('Server listening at {}:{}'.format(host, port))
        while True:
            sock_cli, addr_cli = sock_srv.accept()
            t = threading.Thread(target=handler, args=(sock_cli, addr_cli))
            t.start()


def handler(sock_cli, addr_cli):
    with sock_cli:
        LOG.info('Connected by {}:{}'.format(*addr_cli))
        while True:
            data = sock_cli.recv(4096)
            if not data:
                break
            sock_cli.sendall(data)
    LOG.info('Connection closed {}:{}'.format(*addr_cli))


if __name__ == "__main__":
    server('127.0.0.1', 5000)
