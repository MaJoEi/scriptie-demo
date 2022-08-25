import socket
import pickle
import threading


class Client(threading.Thread):
    s = socket.socket()
    host = socket.gethostname()

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def establish_connection(self, port):
        self.s.connect((self.host, port))

    def send(self, message):
        # self.s.send(message.encode())
        self.s.send(message)

    def receive(self):
        # data = self.s.recv(8192).decode()
        data = self.s.recv(10240)
        if data == "interrupt":
            self.interrupt_connection()
        else:
            return data

    def interrupt_connection(self):
        message = "interrupt"
        self.s.send(message.encode())
        #self.s.close()

