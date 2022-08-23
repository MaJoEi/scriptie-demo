import socket


class Server(object):
    s = socket.socket()
    host = socket.gethostname()
    conn = None

    def __init__(self, port):
        self.port = port
        self.s.bind((self.host, port))

    def establish_connection(self):
        self.s.listen(1)
        self.conn, address = self.s.accept()

    def send(self, message):
        self.conn.send(message.encode())
        return

    def receive(self):
        data = self.conn.recv(1024).decode()
        if data == "interrupt":
            self.interrupt_connection()
        else:
            return data

    def interrupt_connection(self):
        self.conn.close()
