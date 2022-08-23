import socket


class Server(object):
    s = socket.socket()
    host = socket.gethostname()

    def __init__(self, port):
        self.port = port
        self.s.bind((self.host, port))
        self.s.listen(1)

    def send(self, conn, endpoint, message):

        return

    def receive(self):
        return
