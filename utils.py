import socket
def get_myIP():
    hostname = socket.gethostname()
    IP = socket.gethostbyname(hostname)
    return IP