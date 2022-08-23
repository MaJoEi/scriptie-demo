import socket
import threading
import time


class Client(threading.Thread):
    s = socket.socket()
    host = socket.gethostname()

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def establish_connection(self, port):
        self.s.connect((self.host, port))

    def send(self, message):
        self.s.send(message.encode())
        return

    def receive(self):
        data = self.s.recv(1024).decode()
        return data

    def interrupt_connection(self):
        message = "interrupt"
        self.s.send(message.encode())
        #self.s.close()
