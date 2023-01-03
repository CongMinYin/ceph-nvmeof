#
#  Copyright (c) 2021 International Business Machines
#  All rights reserved.
#
#  SPDX-License-Identifier: LGPL-3.0-or-later
#
#  Authors: congmin.yin@intel.com
#

import argparse
import grpc
import json
import logging
from .config import GatewayConfig

import rados
from typing import Dict, Optional

# 用于建立TCP连接
import socket
import threading
import time

class DiscoveryService:
    """Client for gRPC functionality with a gateway server.

    Contains methods to send RPC calls to the server and specifications for the
    associated command line arguments.

    Class attributes:
        cli: Parser object

    Instance attributes: * Must be initialized with DiscoveryService.connect *
        stub: Object on which to call server methods
        logger: Logger instance to track client events
    """
    OMAP_VERSION_KEY = "omap_version"
    BDEV_PREFIX = "bdev_"
    NAMESPACE_PREFIX = "namespace_"
    SUBSYSTEM_PREFIX = "subsystem_"
    HOST_PREFIX = "host_"
    LISTENER_PREFIX = "listener_"

    def __init__(self, config):
        # 原clientinit
        #self._stub = None
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

        # 抄的state的init代码
        self.version = 1
        self.config = config
        self.logger = logging.getLogger(__name__)

        gateway_group = self.config.get("gateway", "group")
        self.omap_name = f"nvmeof.{gateway_group}.state" if gateway_group else "nvmeof.state"

        ceph_pool = self.config.get("ceph", "pool")
        ceph_conf = self.config.get("ceph", "config_file")
        conn = rados.Rados(conffile=ceph_conf)
        conn.connect()
        self.ioctx = conn.open_ioctx(ceph_pool)

        try:
            # Create a new gateway persistence OMAP object
            with rados.WriteOpCtx() as write_op:
                # Set exclusive parameter to fail write_op if object exists
                write_op.new(rados.LIBRADOS_CREATE_EXCLUSIVE)
                self.ioctx.set_omap(write_op, (self.OMAP_VERSION_KEY,),
                                    (str(self.version),))
                self.ioctx.operate_write_op(write_op, self.omap_name)
                self.logger.info(
                    f"First gateway: created object {self.omap_name}")
        except rados.ObjectExists:
            self.logger.info(f"{self.omap_name} omap object already exists.")
        except Exception as ex:
            self.logger.error(f"Unable to create omap: {ex}. Exiting!")
            raise

    def get_subsystems(self, args):
        """Gets subsystems."""

        try:
            req = pb2.get_subsystems_req()
            ret = self.stub.get_subsystems(req)
            subsystems = json.loads(ret.subsystems)
            formatted_subsystems = json.dumps(subsystems, indent=4)
            self.logger.info(f"Get subsystems:\n{formatted_subsystems}")
        except Exception as error:
            self.logger.error(f"Failed to get subsystems: \n {error}")

    def _read_key(self, key) -> Optional[str]:
        """Reads a key from the OMAP and returns its value."""

        with rados.ReadOpCtx() as read_op:
            iter, _ = self.ioctx.get_omap_vals_by_keys(read_op, (key,))
            self.ioctx.operate_read_op(read_op, self.omap_name)
            value_list = list(dict(iter).values())
            if len(value_list) == 1:
                val = str(value_list[0], "utf-8")
                self.logger.debug(f"Read key: {key} -> {val}")
                return val
        return None

    def _read_all(self) -> Dict[str, str]:
        """Reads OMAP and returns dict of all keys and values."""

        with rados.ReadOpCtx() as read_op:
            iter, _ = self.ioctx.get_omap_vals(read_op, "", "", -1)
            self.ioctx.operate_read_op(read_op, self.omap_name)
            omap_dict = dict(iter)
        return omap_dict

    def _get_bdevs(self, omap_dict):
        """Read a bdev from the OMAP."""

        bdevs = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.BDEV_PREFIX):
                # Get bdev_name from end of key
                bdev_name = key.split("_", 1)[1]
                #req = json_format.Parse(val, pb2.create_bdev_req())
                #req.bdev_name = bdev_name
                #callback(req)
                #self.logger.info(f"key: {key}")
                #self.logger.info(f"val: {val}")
                text = val.decode('utf-8')
                # 补充错误处理
                js = json.loads(text)
                #self.logger.info(f"js: {js}")
                #self.logger.info(f"rbd_pool_name: {js['rbd_pool_name']}")
                bdevs.append(js)
                #self.logger.info(f"------------------\n")
        return bdevs

    def _get_subsystems(self, omap_dict):
        """Read a bdev from the OMAP."""

        subsystems = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.SUBSYSTEM_PREFIX):
                # Get bdev_name from end of key
                # bdev_name = key.split("_", 1)[1]
                text = val.decode('utf-8')
                js = json.loads(text)
                subsystems.append(js)
        return subsystems

    def _get_namespaces(self, omap_dict):
        """Read a bdev from the OMAP."""

        namespaces = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.NAMESPACE_PREFIX):
                text = val.decode('utf-8')
                js = json.loads(text)
                namespaces.append(js)
        return namespaces

    def _get_hosts(self, omap_dict):
        """Read a bdev from the OMAP."""

        hosts = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.HOST_PREFIX):
                text = val.decode('utf-8')
                js = json.loads(text)
                hosts.append(js)
        return hosts

    def _get_listeners(self, omap_dict):
        """Read a bdev from the OMAP."""

        listeners = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.LISTENER_PREFIX):
                text = val.decode('utf-8')
                js = json.loads(text)
                listeners.append(js)
        return listeners

    def start_service(self):
        """Enable listening on the server side."""

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('10.239.241.67', 9999))
        # 5指定了连接的最大数量
        s.listen(5)
        self.logger.info("Waiting for connection...")
        while True:
            # 接受一个新连接:
            sock, addr = s.accept()
            # 创建新线程来处理TCP连接:
            t = threading.Thread(target=self.tcplink, args=(sock, addr))
            t.start()

    def tcplink(self, sock, addr):
        self.logger.info('Accept new connection from %s:%s...' % addr)
        #sock.send(b'Welcome!')
        while True:
            data = sock.recv(1024)
            time.sleep(1)
            if not data:
                break
            #sock.send(('Hello, %s!' % data.decode('utf-8')).encode('utf-8'))
            self.logger.info('tcp message:')
            #self.logger.info('%s' % data.decode('utf-8'))
            self.logger.info('%s' % data)
            self.logger.info('%s' % data.decode())
        sock.close()
        print('Connection from %s:%s closed.' % addr)

def main(args=None):
    # Set up root logger
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # 尝试获取omap
    parser = argparse.ArgumentParser(prog="python3 -m control",
                                     description="Discover NVMe gateways")
    parser.add_argument(
        "-c",
        "--config",
        default="ceph-nvmeof.conf",
        type=str,
        help="Path to config file",
    )
    args = parser.parse_args()
    # read config file
    config = GatewayConfig(args.config)

    discovery_service = DiscoveryService(config)
    #discovery_service._read_listener()
    my_omap_dict = discovery_service._read_all()
    logger.info("get omap:")
    logger.info(my_omap_dict)

    # 参考 def restore(self, callbacks): 解析omap
    bdevs = discovery_service._get_bdevs(my_omap_dict)
    subsystems = discovery_service._get_subsystems(my_omap_dict)
    namespaces = discovery_service._get_namespaces(my_omap_dict)
    hosts = discovery_service._get_hosts(my_omap_dict)
    listeners = discovery_service._get_listeners(my_omap_dict)

    # 一个nqn对应一个列表

    # OMAP变化更新

    # 监听变化通知

    # 下面仅用于测试，输出获取的信息
    for bdev in bdevs:
        pass
    logger.info("bdevs")
    logger.info(bdevs)
    logger.info("subsystems")
    logger.info(subsystems)
    logger.info("namespaces")
    logger.info(namespaces)
    logger.info("hosts")
    logger.info(hosts)
    logger.info("listeners")
    logger.info(listeners)

    # 建立TCP监听端口
    # discovery_service.start_service()

if __name__ == "__main__":
    main()
