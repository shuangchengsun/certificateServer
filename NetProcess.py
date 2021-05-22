import struct
from logging.handlers import TimedRotatingFileHandler

import loggerUtil
from CertificateService import *
import logging

msgLen = 4096
LOG_FORMAT = "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
# file_path = "/var/certificate/logs/"
file_path = "./logs/"
log_file = file_path + "certificate.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(filename=log_file, when='D', encoding="utf-8")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(fh)


def netService(tcpClient, clientAddr, ca_auth):
    """
    :param tcpClient: TCP客户端Socket
    :param clientAddr: TCP客户端的地址
    """
    while True:
        # recv_data = tcpClient.recv(4096)
        id = tcpClient.recv(8)
        if len(id) == 0:
            break
        print("id: ", id)
        length = tcpClient.recv(4)
        if len(length) == 0:
            break
        length = int.from_bytes(length, byteorder='big', signed=False)
        print("len: ", length)
        data = tcpClient.recv(length)
        print("data: ", data)
        if len(data) == 0:
            break
        if data:
            host = data.decode()
            t1 = time.time()
            pem_data = ca_auth[host]
            t2 = time.time()
            logger.info("证书签发服务--host: {}, time: {}".format(host, (t2 - t1)))
            tcpClient.send(id)
            length = len(pem_data)
            tcpClient.send(int.to_bytes(length, byteorder="big", length=4))
            tcpClient.send(pem_data)

        # if recv_data:
        #     ser, bus_type, conn_type, content = decoder(recv_data)
        #     msg = b''
        #     if bus_type == 0x01:
        #         # 表示是证书相关的业务
        #         host = content.decode()
        #         t1 = time.time()
        #         pem_data = ca_auth[host]
        #         msg = encoder(ser, 0x01, pem_data)
        #         t2 = time.time()
        #         loggerUtil.info(logger, "证书签发服务--host: ", host, (t2 - t1))
        #     if bus_type == 0x02:
        #         # 表明是心跳数据
        #         msg = encoder(ser, 0x02, b'')
        #         loggerUtil.info(logger, "心跳检测", )
        #     tcpClient.send(msg)
        #     # print("send call")


def encoder(ser, type, data):
    """
    编码解码
    :param data: 需要编码的数据
    """
    '''
    0x01:证书业务
    0x02:心跳
    '''
    bus_type = type
    # 0x01表示长链接，0x02表示断开
    conn_type = 0x01
    # 填充
    empty = 0x00
    # 内容
    content = data
    # 内容的长度
    data_len = len(content)
    # 分割符号
    spilt = b"\r\n"
    total_len = data_len + len(spilt)

    eLen = msgLen - total_len - 12

    fmt = '!ihhhh' + str(data_len) + 's' + str(len(spilt)) + 's'
    if eLen > 0:
        fmt = fmt + str(eLen) + 'x'
    return struct.pack(fmt, ser, bus_type, conn_type, data_len, empty, content, spilt)


def decoder(data):
    """
    :param data: 需要解码的数据
    :rtype: 解码后的数据
    """
    # data = bytearray(data)
    # bus_type = int(data[0:1])
    ser = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]

    bus_type = (data[4] << 8) | data[5]
    conn_type = (data[6] << 8) | data[7]
    data_len = (data[8] << 8) | data[9]
    empty = (data[10] << 8) | data[11]

    content = data[12: 12 + data_len]
    # bus_type, conn_type, data_len, empty, content = struct.unpack(fmt, data)
    return ser, bus_type, conn_type, content
    pass


if __name__ == '__main__':
    message = struct.pack("!i", 2733)
    print(message)
