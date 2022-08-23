import socket


class Client(object):
    s = socket.socket()
    host = socket.gethostname()

    def __init__(self, port):
        self.port = port
        self.s.bind((self.host, port))

    def send(self, conn, endpoint, message):

        return

    def receive(self):

        return
