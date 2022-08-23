import socket


class Client(object):
    s = socket.socket()
    host = socket.gethostname()

    def establish_connection(self, port):
        self.s.bind((self.host, port))
        self.s.connect((self.host, self.port))

    def send(self, message):
        self.s.send(message.encode())
        return

    def receive(self):
        data = self.s.recv(1024).decode()
        return data

    def interrupt_connection(self):
        message = "Interrupt"
        self.s.send(message.encode())
        self.s.close()
