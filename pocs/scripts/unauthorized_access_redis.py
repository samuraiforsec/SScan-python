#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# redis 未授权访问
import socket
from lib.common.utils import save_script_result


ports_to_check = 6379    # 默认扫描端, 会扫描端口是否开放


def do_check(self, url):
    if url != '/':
        return
    port = 6379
    # 非标准端口，不需要检查6379端口是否开放
    # 支持用户传入目标 redis://test.ip:16379 来扫描非标准端口上的Redis服务
    if self.scheme == 'redis' and self.port != 6379:
        port = self.port
    elif 6379 not in self.ports_open:
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((self.host, port))
        # payload = '\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
        # s.send(payload)
        s.send(bytes("INFO\r\n", 'UTF-8'))
        data = s.recv(1024).decode()
        s.close()
        if "redis_version" in data:
            save_script_result(self, '', 'redis://%s:%s' % (self.host, port), 'Redis Unauthorized Access')
    except Exception as e:
        s.close()

