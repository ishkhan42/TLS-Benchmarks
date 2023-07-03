import socket
import ssl


def handle_client(conn):
    conn.recv(4096)
    response = "HTTP/1.1 200 OK"
    conn.sendall(response.encode())


server_socket = None
is_reusing = True

try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8000))
    if is_reusing:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile="./certs/srv.crt", keyfile="./certs/main.key")
        server_socket.listen(32)
        conn, addr = server_socket.accept()
        conn = context.wrap_socket(conn, server_side=True)

    while True:
        if not is_reusing:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                certfile="./certs/srv.crt", keyfile="./certs/main.key")
            server_socket.listen(32)
            conn, addr = server_socket.accept()
            conn = context.wrap_socket(conn, server_side=True)

        handle_client(conn)

        if not is_reusing:
            conn.close()

    if is_reusing:
        conn.close()

except Exception as er:
    print(er)
    server_socket.close()
