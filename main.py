import socket
import threading
from NetProcess import *
from CertificateService import *

if __name__ == '__main__':
    tcpServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 设置socket的属性，程序退出就释放socket
    tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    tcpServer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)

    tcpServer.bind(('', 1212))
    tcpServer.listen(128)
    print("certificate server start ...")
    print("系统配置：")
    print("port: 1212")
    print("SO_SNDBUF: 4194304")
    print("SO_RCVBUF: 4194304")
    ca_auth = CAAuth()
    while True:
        tcpClient, clientAddr = tcpServer.accept()
        thd = threading.Thread(target=netService, args=(tcpClient, clientAddr, ca_auth))
        # 守护线程
        thd.setDaemon(True)
        thd.start()
    pass
