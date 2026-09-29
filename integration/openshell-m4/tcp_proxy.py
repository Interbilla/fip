"""Environment plumbing for one Docker Desktop plus WSL layout.

Docker Desktop's host network is not the Ubuntu distro where the gateway runs.
The proxy listens on the Windows host, which containers reach as
host.docker.internal, and forwards TCP to the WSL gateway. It does not
terminate TLS. It is not a FIP grant, not an OpenShell policy, and not
required on a host where the gateway and the sandbox share a network namespace.
"""

import socket
import sys
import threading


def pump(source, sink):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        for sock, how in ((source, socket.SHUT_RD), (sink, socket.SHUT_WR)):
            try:
                sock.shutdown(how)
            except OSError:
                pass


def handle(client, target):
    remote = socket.create_connection(target)
    left = threading.Thread(target=pump, args=(client, remote), daemon=True)
    right = threading.Thread(target=pump, args=(remote, client), daemon=True)
    left.start()
    right.start()
    left.join()
    right.join()
    client.close()
    remote.close()


def main():
    listen = (sys.argv[1], int(sys.argv[2]))
    target = (sys.argv[3], int(sys.argv[4]))
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(listen)
    server.listen()
    while True:
        client, _addr = server.accept()
        threading.Thread(target=handle, args=(client, target), daemon=True).start()


if __name__ == "__main__":
    main()
