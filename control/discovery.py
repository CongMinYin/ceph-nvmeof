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

import socket
import threading
import time
import struct

# nvme tcp pdu type
NVME_TCP_ICREQ = 0x0,
NVME_TCP_ICRESP = 0x1,
NVME_TCP_H2C_TERM = 0x2,
NVME_TCP_C2H_TERM = 0x3,
NVME_TCP_CMD = 0x4,
NVME_TCP_RSP = 0x5,
NVME_TCP_H2C_DATA = 0x6,
NVME_TCP_C2H_DATA = 0x7,
NVME_TCP_R2T = 0x9,

# nvme tcp fabric command
NVME_FABRIC_OPC = 0x7F

# nvme tcp fabric command type
NVME_FCTYPE_PROP_SET = 0x0
NVME_FCTYPE_CONNECT = 0x1
NVME_FCTYPE_PROP_GET = 0x4
NVME_FCTYPE_AUTH_SEND = 0x5
NVME_FCTYPE_AUTH_RECV = 0x6
NVME_FCTYPE_DISCONNECT = 0x8


class DiscoveryService:
    """Implements discovery controller.

    Response discover request from initiator.

    Instance attributes:
        version: Discovery controller version
        config: Basic gateway parameters
        logger: Logger instance to track discovery controller events
        omap_name: OMAP object name
        ioctx: I/O context which allows OMAP access
        discovery_addr: Discovery controller addr which allows initiator send command
        discovery_port: Discovery controller's listening port
    """

    BDEV_PREFIX = "bdev_"
    NAMESPACE_PREFIX = "namespace_"
    SUBSYSTEM_PREFIX = "subsystem_"
    HOST_PREFIX = "host_"
    LISTENER_PREFIX = "listener_"

    def __init__(self, config):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level=logging.INFO)

        self.version = 1
        self.config = config

        gateway_group = self.config.get("gateway", "group")
        self.omap_name = f"nvmeof.{gateway_group}.state" if gateway_group else "nvmeof.state"
        self.logger.info(f"omap_name: {self.omap_name}")

        ceph_pool = self.config.get("ceph", "pool")
        ceph_conf = self.config.get("ceph", "config_file")
        conn = rados.Rados(conffile=ceph_conf)
        conn.connect()
        self.ioctx = conn.open_ioctx(ceph_pool)

        self.discovery_addr = self.config.get("discovery", "addr")
        self.discovery_port = self.config.get("discovery", "port")
        self.logger.info(f"discovery addr: {self.discovery_addr} port: {self.discovery_port}")

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
                text = val.decode('utf-8')
                # 补充错误处理
                js = json.loads(text)
                bdevs.append(js)
        return bdevs

    def _get_subsystems(self, omap_dict):
        """Read a bdev from the OMAP."""

        subsystems = []
        for (key, val) in omap_dict.items():
            if key.startswith(self.SUBSYSTEM_PREFIX):
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

    def reply_initialize(self, sock):
        """Enable listening on the server side."""

        self.logger.debug("handle ICreq.")
        # reply
        reply = bytearray(128)
        # PDU
        # PDU type: NVME_TCP_ICRESP
        reply[0] = 0x01
        # PDU specical flag
        reply[1] = 0x00
        # PDU header length
        reply[2] = 0x80
        # PDU data offset
        reply[3] = 0x00
        # packet length
        reply[4:8] = b'\x80\x00\x00\x00'
        self.logger.debug(f'reply initialize connection request: len: {len(reply)} reply: {reply.hex()}')
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.error('Client disconnected unexpectedly.')
            raise
        self.logger.debug('reply initialize connection request.')


    def nvmeof_tcp_connection(self, sock, addr):
        self.logger.info('Accept new connection from %s:%s...' % addr)
        # Some common variables that may be used multiple times
        nvmeof_connect_data_hostid = ()
        nvmeof_connect_data_cntlid = 0
        nvmeof_connect_data_subnqn = ()
        nvmeof_connect_data_hostnqn = ()
        log_page = bytes()
        log_page_len = 0
        generation_counter = 1
        shutdown_notification = 0
        shutdown_now = 0

        try:
          while True:
            head = sock.recv(1024)
            if not head:
                time.sleep(0.01)
                continue

            PDU = struct.unpack_from('<BBBBI', head, 0)
            pdu_type = PDU[0]
            PSH_flag = PDU[1]
            PH_len = PDU[2]
            PH_off = PDU[3]
            package_len = PDU[4]

            self.logger.debug('------new message-------')
            self.logger.debug(f'pdu_type: {pdu_type}')
            self.logger.debug(f'PSH_flag: {PSH_flag}')
            self.logger.debug(f'PH_len: {PH_len}')
            self.logger.debug(f'PH_off: {PH_off}')
            self.logger.debug(f'package_len: {package_len}')

            # If the length exceeds one packet, continue to recive
            buffer = [head]
            if package_len > 1024:
                i = package_len // 1024
                if package_len % 1024 == 0:
                    i -= 1
                #self.logger.debug(f"i: {i}")
                while i > 0:
                    d = sock.recv(1024)
                    if d:
                        buffer.append(d)
                        i -= 1
                    else:
                        break
            data = b''.join(buffer)
            #self.logger.debug('pdu package:')
            #self.logger.debug(f"len: {len(data)} data: {data.hex()}")

            # ICreq
            if pdu_type == 0:
                self.reply_initialize(sock)

            # CMD
            if pdu_type == 4:
                CMD1 = struct.unpack_from('<BBH', data, 8)
                opcode = CMD1[0]
                reserved = CMD1[1]
                cmd_id = CMD1[2]
                self.logger.debug(f'opcode: {hex(opcode)}')
                #self.logger.debug(f'reserved: {hex(reserved)}')
                self.logger.debug(f'cmd_id: {hex(cmd_id)}')

                # fabric command
                if opcode == 0x7f:
                    fabric_cmd_type = struct.unpack_from('<B', data, 12)[0]
                    self.logger.debug(f'fabric_cmd_type: {hex(fabric_cmd_type)}')

                    # connect, dissect_nvmeof_fabric_connect_cmd， NVME_FCTYPE_CONNECT
                    if fabric_cmd_type == 0x01:
                        self.logger.debug("********handle NVME_FCTYPE_CONNECT.********")
                        hf_nvmeof_cmd_connect_rsvd1 = struct.unpack_from('<19B', data, 13)
                        SIGL1 = struct.unpack_from('<QI4B', data, 32)
                        address = SIGL1[0]
                        length = SIGL1[1]
                        #reserved3 = SIGL1[2]
                        #前4位是descriptor type(0x0)，后4位是descriptor sub type(0x1)
                        descriptor_type = SIGL1[5]
                        self.logger.debug(f'address: {hex(address)}')
                        self.logger.debug(f'length: {length}')
                        self.logger.debug(f'descriptor_type: {descriptor_type}')

                        CMD2 = struct.unpack_from('<HHHBBI', data, 48)
                        record_format = CMD2[0]
                        queue_id = CMD2[1]
                        submission_queue_size = CMD2[2]
                        connect_attributes = CMD2[3]
                        keep_alive_timeout = CMD2[5]
                        self.logger.debug(f'record_format: {record_format}')
                        self.logger.debug(f'queue_id: {queue_id}')
                        self.logger.debug(f'submission_queue_size: {submission_queue_size}')
                        self.logger.debug(f'connect_attributes: {connect_attributes}')
                        self.logger.debug(f'keep_alive_timeout: {keep_alive_timeout}')

                        # Data
                        nvmeof_connect_data_hostid = struct.unpack_from('<16B', data, 72)
                        hex_list = [hex(i) for i in nvmeof_connect_data_hostid]
                        nvmeof_connect_data_hostid_string = ''.join(hex_list)
                        nvmeof_connect_data_cntlid = struct.unpack_from('<H', data, 88)[0]
                        nvmeof_connect_data_subnqn = struct.unpack_from('<256B', data, 328)
                        hex_list = [hex(i) for i in nvmeof_connect_data_subnqn]
                        nvmeof_connect_data_subnqn_string = ''.join(hex_list)
                        nvmeof_connect_data_hostnqn = struct.unpack_from('<256B', data, 584)
                        hex_list = [hex(i) for i in nvmeof_connect_data_hostnqn]
                        nvmeof_connect_data_hostnqn_string = ''.join(hex_list)
                        self.logger.debug(f'hostid: {nvmeof_connect_data_hostid_string}')
                        self.logger.debug(f'nvmeof_connect_data_cntlid: {nvmeof_connect_data_cntlid}')
                        self.logger.debug(f'subsystem_nqn: {nvmeof_connect_data_subnqn_string}')
                        self.logger.debug(f'host_nqn: {nvmeof_connect_data_hostnqn_string}')

                        # reply
                        reply = bytearray(24)
                        # PDU
                        # PDU type: capsule response
                        reply[0] = 0x05
                        # PDU specical flag
                        reply[1] = 0x00
                        # PDU header length
                        reply[2] = 0x18
                        # PDU data offset
                        reply[3] = 0x00
                        # packet length
                        reply[4:8] = b'\x18\x00\x00\x00'
                        # Cqe for cmd connect
                        #controller id, 这个值经过实验不是固定的，01/03都有
                        reply[8:10] = b'\x01\x00'
                        # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                        reply[16:18] = b'\x01\x00'
                        self.logger.debug(f'send SQ head pointer: {reply[16:18]}')
                        self.logger.debug(f'len: {len(reply)} connect reply: {reply.hex()}')
                        try:
                            sock.sendall(reply)
                        except BrokenPipeError:
                            self.logger.debug('Client disconnected unexpectedly.')
                            break
                        self.logger.debug('reply connect request.')
                        self.logger.debug('--------------------------------------------------------\n')

                    # dissect_nvmeof_fabric_cmd
                    # NVME_FCTYPE_PROP_GET
                    if fabric_cmd_type == 0x04:
                        self.logger.debug("********************************************\n")
                        self.logger.debug("********handle NVME_FCTYPE_PROP_GET.********")
                        # 第35个byte有值，0x5a
                        hf_nvmeof_cmd_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
                        # 0x01 代表property size是8byte
                        hf_nvmeof_cmd_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
                        hf_nvmeof_cmd_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
                        hf_nvmeof_cmd_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]
                        self.logger.debug(f'hf_nvmeof_cmd_prop_get_set_attrib: {hex(hf_nvmeof_cmd_prop_get_set_attrib)}')
                        self.logger.debug(f'hf_nvmeof_cmd_prop_get_set_offset: {hex(hf_nvmeof_cmd_prop_get_set_offset)}')

                        # reply
                        reply = bytearray(24)
                        # PDU
                        # PDU type: capsule response
                        reply[0] = 0x05
                        # PDU specical flag
                        reply[1] = 0x00
                        # PDU header length
                        reply[2] = 0x18
                        # PDU data offset
                        reply[3] = 0x00
                        # packet length
                        reply[4:8] = b'\x18\x00\x00\x00'

                        # Cqe for cmd property get
                        # controller capabilities
                        if hf_nvmeof_cmd_prop_get_set_offset == 0x00000000:
                            self.logger.debug("********handle controller capabilities.********")
                            reply[8:16] = b'\x7f\x00\x01\x1e\x20\x00\x00\x00'
                            # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                            reply[16:18] = b'\x02\x00'
                        # controller configuration
                        if hf_nvmeof_cmd_prop_get_set_offset == 0x00000014:
                            # 正常不会走到这里，configuration是set的部分，这里是get
                            self.logger.debug("XXXXXXXXXXXXXX error XXXXXXXXXXXXXXXXX")
                            # self.logger.debug("********handle controller configuration.********")
                            # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                            # reply[16:18] = b'\x03\x00'
                        # controller status
                        if hf_nvmeof_cmd_prop_get_set_offset == 0x0000001c:
                            self.logger.debug("********handle controller status.********")
                            if shutdown_notification == 0:
                                reply[8:16] = b'\x01\x00\x00\x00\x00\x00\x00\x00'
                                # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                                reply[16:18] = b'\x04\x00'
                            else:
                                # here shutdown_notification should be 0x1
                                reply[8:16] = b'\x09\x00\x00\x00\x00\x00\x00\x00'
                                # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                                reply[16:18] = b'\x0e\x00'
                                shutdown_now = 1
                        # version
                        if hf_nvmeof_cmd_prop_get_set_offset == 0x00000008:
                            self.logger.debug("********handle version.********")
                            # 这个版本号也不知道哪来的
                            reply[8:16] = b'\x00\x03\x01\x00\x00\x00\x00\x00'
                            # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                            reply[16:18] = b'\x05\x00'
                        self.logger.debug(f'send SQ head pointer: {reply[16:18]}')
                        # SQ id, 可以省略
                        reply[18:20] = b'\x00\x00'
                        # command id，与收包的command的id相同
                        reply[20:22] = struct.pack('<H', cmd_id)
                        self.logger.debug(f'send command id : {reply[20:22].hex()} recive cmd_id: {hex(cmd_id)}')
                        # status filed
                        reply[22:24] = b'\x00\x00'
                        self.logger.debug(f'len: {len(reply)} NVME_FCTYPE_PROP_GET reply: {reply.hex()}')
                        try:
                            sock.sendall(reply)
                        except BrokenPipeError:
                            self.logger.debug('Client disconnected unexpectedly.')
                            break
                        self.logger.debug('reply NVME_FCTYPE_PROP_GET request.')
                        self.logger.debug('--------------------------------------------------------\n')

                    # NVME_FCTYPE_PROP_SET
                    if fabric_cmd_type == 0x00:
                        self.logger.debug("********************************************\n")
                        self.logger.debug("********handle NVME_FCTYPE_PROP_SET.********")
                        # 第35个byte有值，0x5a
                        hf_nvmeof_cmd_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
                        # 0x01 代表property size是8byte
                        hf_nvmeof_cmd_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
                        hf_nvmeof_cmd_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
                        hf_nvmeof_cmd_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]
                        self.logger.debug(f'hf_nvmeof_cmd_prop_get_set_attrib: {hex(hf_nvmeof_cmd_prop_get_set_attrib)}')
                        self.logger.debug(f'hf_nvmeof_cmd_prop_get_set_offset: {hex(hf_nvmeof_cmd_prop_get_set_offset)}')
                        # 看wireshark会根据不太的attr和offset进行不同的解析，但是对于discovery命令，貌似只有一种情况
                        controller_configuration = struct.unpack_from('<4B', data, 56)
                        shutdown_notification = (controller_configuration[1] >> 6) & 0x3
                        self.logger.debug(f'shutdown_notification: {hex(shutdown_notification)}')

                        # NVMeOF Property Set Controller Configuration
                        # if hf_nvmeof_cmd_prop_get_set_offset == 0x14
                        # reply
                        reply = bytearray(24)
                        # PDU
                        # PDU type: capsule response
                        reply[0] = 0x05
                        # PDU specical flag
                        reply[1] = 0x00
                        # PDU header length
                        reply[2] = 0x18
                        # PDU data offset
                        reply[3] = 0x00
                        # packet length
                        reply[4:8] = b'\x18\x00\x00\x00'

                        # Cqe for cmd property set
                        # if hf_nvmeof_cmd_prop_get_set_offset == 0x00000014:
                        # SQ head pointer, 前一个命令回复的SQ Head Poiner+1
                        if shutdown_notification == 0:
                            reply[16:18] = b'\x03\x00'
                        else:
                            reply[16:18] = b'\x0d\x00'
                        self.logger.debug(f'send SQ head pointer: {reply[16:18]}')
                        # SQ id, 可以省略
                        reply[18:20] = b'\x00\x00'
                        # command id，与收包的command的id相同
                        reply[20:22] = struct.pack('<H', cmd_id)
                        self.logger.debug(f'send command id: {reply[20:22].hex()} recive cmd_id: {hex(cmd_id)}')
                        # status filed
                        reply[22:24] = b'\x00\x00'
                        self.logger.debug(f'len: {len(reply)} NVME_FCTYPE_PROP_SET reply: {reply.hex()}')
                        try:
                            sock.sendall(reply)
                        except BrokenPipeError:
                            self.logger.debug('Client disconnected unexpectedly.')
                            break
                        self.logger.debug('reply NVME_FCTYPE_PROP_SET request.')
                        self.logger.debug('--------------------------------------------------------\n')

                    # NVME_FCTYPE_AUTH_SEND
                    if fabric_cmd_type == 0x05:
                        self.logger.debug("********************************************\n")
                        self.logger.debug("********prepare handle NVME_FCTYPE_AUTH_SEND.********")
                        self.logger.debug("can't handle.")
                    # NVME_FCTYPE_AUTH_RECV
                    if fabric_cmd_type == 0x06:
                        self.logger.debug("********************************************\n")
                        self.logger.debug("********prepare handle NVME_FCTYPE_AUTH_RECV.********")
                        self.logger.debug("can't handle.")
                    # NVME_FCTYPE_DISCONNECT
                    if fabric_cmd_type == 0x08:
                        self.logger.debug("********************************************\n")
                        self.logger.debug("********prepare handle NVME_FCTYPE_DISCONNECT.********")
                        self.logger.debug("can't handle.")

                # NVME_AQ_OPC_GET_LOG_PAGE
                if opcode == 0x02:
                    self.logger.debug("********************************************\n")
                    self.logger.debug("********prepare handle NVME_AQ_OPC_GET_LOG_PAGE.********")
                    my_omap_dict = self._read_all()
                    listeners = self._get_listeners(my_omap_dict)
                    self.logger.debug(listeners)

                    hf_nvme_cmd_nsid = struct.unpack_from('<I', data, 12)[0]
                    hf_nvme_cmd_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
                    hf_nvme_cmd_mptr = struct.unpack_from('<Q', data, 24)[0]
                    hf_nvme_cmd_sgl = struct.unpack_from('<16B', data, 32)
                    # descriptor type:0x5, descriptor sub type:0xa
                    hf_nvme_cmd_sgl_desc_type = hf_nvme_cmd_sgl[15] & 0xF0
                    hf_nvme_cmd_sgl_desc_sub_type = hf_nvme_cmd_sgl[15] & 0x0F
                    hf_nvme_get_logpage_dword10 = struct.unpack_from('<I', data, 48)[0]
                    # it is the bytes when reply, rule: (values+1)*4
                    # for example, hf_nvme_get_logpage_numd = 511, should reply 2048bytes
                    # for example, hf_nvme_get_logpage_numd = 511, should reply 2048bytes
                    hf_nvme_get_logpage_numd = struct.unpack_from('<I', data, 50)[0]
                    hf_nvme_get_logpage_dword11 = struct.unpack_from('<I', data, 52)[0]
                    # Logpage offset overlaps with dword13
                    hf_nvme_logpage_offset = struct.unpack_from('<Q', data, 56)[0]
                    hf_nvme_get_logpage_dword13 = struct.unpack_from('<I', data, 60)[0]
                    hf_nvme_get_logpage_dword14 = struct.unpack_from('<I', data, 64)[0]
                    hf_nvme_get_logpage_dword15 = struct.unpack_from('<I', data, 68)[0]
                    get_logpage_lid = hf_nvme_get_logpage_dword10 & 0xFF
                    get_logpage_lsp = (hf_nvme_get_logpage_dword10 >> 8) & 0x1F
                    get_logpage_lsi = hf_nvme_get_logpage_dword11 >> 16
                    get_logpage_uid_idx = hf_nvme_get_logpage_dword14 & 0x3F
                    self.logger.debug(f'hf_nvme_cmd_nsid: {hex(hf_nvme_cmd_nsid)}')
                    self.logger.debug(f'hf_nvme_cmd_rsvd1: {hex(hf_nvme_cmd_rsvd1)}')
                    self.logger.debug(f'hf_nvme_cmd_mptr: {hex(hf_nvme_cmd_mptr)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_type: {hex(hf_nvme_cmd_sgl_desc_type)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_sub_type: {hex(hf_nvme_cmd_sgl_desc_sub_type)}')
                    self.logger.debug(f'hf_nvme_identify_dword10: {hex(hf_nvme_get_logpage_dword10)}')
                    self.logger.debug(f'hf_nvme_identify_dword11: {hex(hf_nvme_get_logpage_dword11)}')
                    self.logger.debug(f'hf_nvme_logpage_offset, should be 0x0: {hex(hf_nvme_logpage_offset)}')
                    self.logger.debug(f'hf_nvme_identify_dword13: {hex(hf_nvme_get_logpage_dword13)}')
                    self.logger.debug(f'hf_nvme_identify_dword14: {hex(hf_nvme_get_logpage_dword14)}')
                    self.logger.debug(f'hf_nvme_identify_dword15: {hex(hf_nvme_get_logpage_dword15)}')
                    self.logger.debug(f'get_logpage_lid, should be 0x70: {hex(get_logpage_lid)}')
                    self.logger.debug(f'get_logpage_lsp, should be 0x00: {hex(get_logpage_lsp)}')
                    self.logger.debug(f'get_logpage_lsi, should be 0x0000: {hex(get_logpage_lsi)}')
                    self.logger.debug(f'get_logpage_uid_idx, should be 0x00: {hex(get_logpage_uid_idx)}')

                    if get_logpage_lid != 0x70:
                        self.logger.error(f'request type error. It is not discovery request.')
                        return

                    # 根据收到get log page请求包进行回复，主要依据是数据包长度
                    nvme_data_len = (hf_nvme_get_logpage_numd + 1) * 4
                    self.logger.debug(f'nvme_data_len: {nvme_data_len}')

                    # NVMe Express
                    # 提前准备所有的log page数据段，这部分代码可以移动到下面的判断中去
                    if log_page_len == 0 and nvme_data_len > 16:
                        log_page_len = 1024 * (len(listeners) + 1)
                        log_page = bytearray(log_page_len)
                        self.logger.debug(f'log_page_len: {log_page_len}')
                        # the first 1024 bytes
                        # generation counter
                        log_page[0:8] = struct.pack('<Q', generation_counter)
                        # number of records
                        log_page[8:16] = struct.pack('<Q', len(listeners))
                        # record format
                        log_page[16:18] = b'\x00\x00'

                        # the log entry pary
                        log_entry_counter = 0
                        while log_entry_counter < len(listeners):
                            # create a "pointer" to the log_entry
                            log_entry = bytearray(1024)
                            self.logger.debug(f'log_entry len: {len(log_entry)}')
                            # transport type: TCP
                            log_entry[0] = 0x03
                            # address family: AF_INET
                            log_entry[1] = 0x01
                            # subsystem type: NVM system with IO controller(不知道对不对，从spdk收集的)
                            log_entry[2] = 0x02
                            # transport requirement
                            log_entry[3] = 0x02
                            # port ID
                            log_entry[4:6] = struct.pack('<H', log_entry_counter)
                            # controller ID
                            log_entry[6:8] = b'\xff\xff'
                            # admin max SQ size
                            log_entry[8:10] = b'\x80\x00'
                            # skip reserved
                            # transport service indentifier(TRSVCID)
                            log_entry[32:64] = str(listeners[log_entry_counter]["trsvcid"]).encode().ljust(32, b'\x20')
                            '''
                            if listeners[log_entry_counter]["trsvcid"] > 65535 or listeners[log_entry_counter]["trsvcid"] < 0:
                                self.logger.error(f'port error: {listeners[log_entry_counter]["trsvcid"]}')
                                return
                            else:
                                log_page[32:64] = str(listeners[log_entry_counter]["trsvcid"]).encode().ljust(32, b'\x20')
                            '''
                            # skip reserved
                            # NVM subsystem qualified name(nqn)
                            log_entry[256:512] = str(listeners[log_entry_counter]["nqn"]).encode().ljust(256, b'\x00')
                            # Transport address(traddr)
                            log_entry[512:768] = str(listeners[log_entry_counter]["traddr"]).encode().ljust(256, b'\x20')
                            # skip transport sepcific address subtype(tsas)
                            log_page[1024*(log_entry_counter+1):1024*(log_entry_counter+2)] = log_entry
                            #self.logger.debug(f'log_entry: {log_entry}')
                            log_entry_counter += 1
                            self.logger.debug(f'log_entry_counter: {log_entry_counter}')
                        self.logger.debug(f'log_page len: {len(log_page)}')
                        self.logger.debug('\n\n')
                        #self.logger.debug(f'log_page: {log_page}')
                    else:
                        self.logger.debug(f'still in process of sending log page...')


                    # 根据收到get log page请求包进行回复，主要依据是数据包长度
                    if nvme_data_len == 16:
                        # reply
                        reply = bytearray(40)
                        # PDU
                        # PDU type: C2HDdata
                        reply[0] = 0x07
                        # PDU specical flag
                        reply[1] = 0x0c
                        # PDU header length
                        reply[2] = 0x18
                        # PDU data offset
                        reply[3] = 0x18
                        # packet length
                        reply[4:8] = b'\x28\x00\x00\x00'

                        # NVMe/TCP Data PDU
                        # command id，与收包的command的id相同
                        reply[8:10] = struct.pack('<H', cmd_id)
                        self.logger.debug(f'send command id : {reply[8:10].hex()} recive cmd_id: {hex(cmd_id)}')
                        # transfer tag
                        reply[10:12] = b'\x00\x00'
                        # data offset
                        reply[12:16] = b'\x00\x00\x00\x00'
                        # data length
                        reply[16:20] = b'\x10\x00\x00\x00'

                        # NVMe Express
                        # generation counter
                        # 这个或许要从1开始累加,跟下面一样pack进去
                        reply[24:32] = struct.pack('<Q', generation_counter)
                        # number of records
                        reply[32:40] = struct.pack('<Q', len(listeners))
                        self.logger.debug(f'len: {len(reply)} NVME_AQ_OPC_GET_LOG_PAGE reply: {reply.hex()}')
                        try:
                            sock.sendall(reply)
                        except BrokenPipeError:
                            self.logger.debug('Client disconnected unexpectedly.')
                            break
                    elif nvme_data_len > 16 and nvme_data_len % 1024 == 0:
                        # reply
                        nvme_tcp_head_len = 24
                        reply = bytearray(nvme_tcp_head_len)
                        # PDU
                        # PDU type: C2HDdata
                        reply[0] = 0x07
                        # PDU specical flag
                        reply[1] = 0x0c
                        # PDU header length
                        reply[2] = 0x18
                        # PDU data offset
                        reply[3] = 0x18
                        reply[4:8] = struct.pack('<I', nvme_tcp_head_len + nvme_data_len)
                        self.logger.debug(f'reply len: {nvme_tcp_head_len + nvme_data_len}')

                        # NVMe/TCP Data PDU
                        # command id，与收包的command的id相同
                        reply[8:10] = struct.pack('<H', cmd_id)
                        self.logger.debug(f'send command id : {reply[8:10].hex()} recive cmd_id: {hex(cmd_id)}')
                        # transfer tagself.logger.debug('\n\n')
                        reply[10:12] = b'\x00\x00'
                        # data offset
                        reply[12:16] = b'\x00\x00\x00\x00'
                        # data length
                        reply[16:20] = struct.pack('<I', nvme_data_len)
                        self.logger.debug(f'data len: {nvme_data_len}')
                        self.logger.debug(f'reply : {reply}')

                        # NVMe Express
                        reply = bytes(reply) + bytes(log_page[0:nvme_data_len])
                        log_page = log_page[nvme_data_len:]
                        log_page_len -= nvme_data_len
                        self.logger.debug(f'remaining log_page_len: {log_page_len}')
                        self.logger.debug(f'reply len: {len(reply)} reply: {reply}')
                        self.logger.debug('\n\n')
                        self.logger.debug(f'len: {len(reply)} NVME_AQ_OPC_GET_LOG_PAGE reply: {reply.hex()}')
                        try:
                            sock.sendall(reply)
                        except BrokenPipeError:
                            self.logger.debug('Client disconnected unexpectedly.')
                            break
                    else:
                        self.logger.error(f'lenghth error. It need be 16 or n*1024')
                        return
                    self.logger.debug('reply NVME_AQ_OPC_GET_LOG_PAGE request.')
                    self.logger.debug('--------------------------------------------------------\n')

                # NVME_AQ_OPC_IDENTIFY
                if opcode == 0x06:
                    self.logger.debug("********************************************\n")
                    self.logger.debug("********handle NVME_AQ_OPC_IDENTIFY.********")
                    hf_nvme_cmd_nsid = struct.unpack_from('<I', data, 12)[0]
                    hf_nvme_cmd_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
                    hf_nvme_cmd_mptr = struct.unpack_from('<Q', data, 24)[0]
                    hf_nvme_cmd_sgl = struct.unpack_from('<16B', data, 32)
                    # descriptor type:0x5, descriptor sub type:0xa
                    hf_nvme_cmd_sgl_desc_type = hf_nvme_cmd_sgl[15] & 0xF0
                    hf_nvme_cmd_sgl_desc_sub_type = hf_nvme_cmd_sgl[15] & 0x0F
                    hf_nvme_identify_dword10 = struct.unpack_from('<I', data, 48)[0]
                    hf_nvme_identify_dword11 = struct.unpack_from('<I', data, 52)[0]
                    hf_nvme_identify_dword12 = struct.unpack_from('<I', data, 56)[0]
                    hf_nvme_identify_dword13 = struct.unpack_from('<I', data, 60)[0]
                    hf_nvme_identify_dword14 = struct.unpack_from('<I', data, 64)[0]
                    hf_nvme_identify_dword15 = struct.unpack_from('<I', data, 68)[0]
                    self.logger.debug(f'hf_nvme_cmd_nsid: {hex(hf_nvme_cmd_nsid)}')
                    self.logger.debug(f'hf_nvme_cmd_rsvd1: {hex(hf_nvme_cmd_rsvd1)}')
                    self.logger.debug(f'hf_nvme_cmd_mptr: {hex(hf_nvme_cmd_mptr)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_type: {hex(hf_nvme_cmd_sgl_desc_type)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_sub_type: {hex(hf_nvme_cmd_sgl_desc_sub_type)}')
                    self.logger.debug(f'hf_nvme_identify_dword10: {hex(hf_nvme_identify_dword10)}')
                    self.logger.debug(f'hf_nvme_identify_dword11: {hex(hf_nvme_identify_dword11)}')
                    self.logger.debug(f'hf_nvme_identify_dword12: {hex(hf_nvme_identify_dword12)}')
                    self.logger.debug(f'hf_nvme_identify_dword13: {hex(hf_nvme_identify_dword13)}')
                    self.logger.debug(f'hf_nvme_identify_dword14: {hex(hf_nvme_identify_dword14)}')
                    self.logger.debug(f'hf_nvme_identify_dword15: {hex(hf_nvme_identify_dword15)}')

                    # reply
                    reply = bytearray(4120)
                    # PDU
                    # PDU type:C2HData
                    reply[0] = 0x07
                    # PDU specific flags
                    reply[1] = 0x0c
                    # PDU header length
                    reply[2] = 0x18
                    # PDU data offset
                    reply[3] = 0x18
                    # packet length
                    reply[4:8] = b'\x18\x10\x00\x00'

                    # NVMe/TCP Data PDU
                    # command id，与收包的command的id相同
                    reply[8:10] = struct.pack('<H', cmd_id)
                    self.logger.debug(f'send command id : {reply[8:10].hex()} recive cmd_id: {hex(cmd_id)}')
                    # transfer tag
                    reply[10:12] = b'\x00\x00'
                    # data offset
                    reply[12:16] = b'\x00\x00\x00\x00'
                    # data length
                    reply[16:20] = b'\x00\x10\x00\x00'

                    # NVM Express
                    # There are too many fields in this section, omitting parts with values of 0
                    # firmware revision
                    # 这个怎么获combined_reply取？？？？
                    reply[88:96] = b'\x32\x33\x2e\x30\x35\x20\x20\x20'
                    # maximum data transfer size
                    reply[101] = 0x05
                    # controller ID
                    # 这个不知道是固定的还是怎么得来的
                    reply[102:104] = b'\x01\x00'
                    # version
                    reply[104:108] = b'\x00\x03\x01\x00'
                    # optional asynchronous envents supported
                    reply[116:120] = b'\x00\x00\x00\x80'
                    # asynchronous envents request limit
                    reply[283] = 0x03
                    # log page attributes(LPA):True
                    reply[285] = 0x04
                    # error log page entries(ELPE):0x7f:(128 entries)
                    reply[286] = 0x7f
                    # maximum outstanding commands:128
                    reply[538:540] = b'\x80\x00'
                    # fused operation support
                    reply[546:548] = b'\x01\x00'
                    # SGL support
                    reply[560:564] = b'\x05\x00\x10\x00'
                    # NVM subsystem NVMe qualified name
                    # NVM Subsystem NVMe Qualified Name (SUBNQN): nqn.2014-08.org.nvmexpress.discovery
                    # 从connect命令获取过来的，但不知道connect命令哪来的这个
                    #self.logger.debug(f'reply nvmeof_connect_data_subnqn_string: {nvmeof_connect_data_subnqn_string}')
                    #self.logger.debug(f'reply nvmeof_connect_data_subnqn: {nvmeof_connect_data_subnqn}')
                    # reply[792:1048] = struct.pack('<256B', nvmeof_connect_data_subnqn)
                    for i in range(256):
                        reply[792+i] = nvmeof_connect_data_subnqn[i]
                    #self.logger.debug(f'reply nvmeof_connect_data_subnqn_string: {reply[792:1048]}')

                    self.logger.debug(f'len: {len(reply)} NVME_AQ_OPC_IDENTIFY reply: {reply.hex()}')
                    try:
                        sock.sendall(reply)
                    except BrokenPipeError:
                        self.logger.debug('Client disconnected unexpectedly.')
                        break
                    self.logger.debug('reply NVME_AQ_OPC_IDENTIFY request.')
                    self.logger.debug('--------------------------------------------------------\n')

                # NVME_AQ_OPC_SET_FEATURE
                if opcode == 0x09:
                    self.logger.debug("********************************************\n")
                    self.logger.debug("********handle NVME_AQ_OPC_SET_FEATURE.********")
                    hf_nvme_cmd_nsid = struct.unpack_from('<I', data, 12)[0]
                    hf_nvme_cmd_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
                    hf_nvme_cmd_mptr = struct.unpack_from('<Q', data, 24)[0]
                    hf_nvme_cmd_sgl = struct.unpack_from('<16B', data, 32)
                    # descriptor type:0x5, descriptor sub type:0xa
                    hf_nvme_cmd_sgl_desc_type = hf_nvme_cmd_sgl[15] & 0xF0
                    hf_nvme_cmd_sgl_desc_sub_type = hf_nvme_cmd_sgl[15] & 0x0F
                    hf_nvme_set_features_dword10 = struct.unpack_from('<I', data, 48)[0]
                    hf_nvme_set_features_dword11 = struct.unpack_from('<I', data, 52)[0]
                    hf_nvme_set_features_dword12 = struct.unpack_from('<I', data, 56)[0]
                    hf_nvme_set_features_dword13 = struct.unpack_from('<I', data, 60)[0]
                    hf_nvme_set_features_dword14 = struct.unpack_from('<I', data, 64)[0]
                    hf_nvme_set_features_dword15 = struct.unpack_from('<I', data, 68)[0]
                    self.logger.debug(f'hf_nvme_cmd_nsid: {hex(hf_nvme_cmd_nsid)}')
                    self.logger.debug(f'hf_nvme_cmd_rsvd1: {hex(hf_nvme_cmd_rsvd1)}')
                    self.logger.debug(f'hf_nvme_cmd_mptr: {hex(hf_nvme_cmd_mptr)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_type: {hex(hf_nvme_cmd_sgl_desc_type)}')
                    self.logger.debug(f'hf_nvme_cmd_sgl_desc_sub_type: {hex(hf_nvme_cmd_sgl_desc_sub_type)}')
                    self.logger.debug(f'hf_nvme_identify_dword10: {hex(hf_nvme_set_features_dword10)}')
                    self.logger.debug(f'hf_nvme_identify_dword11: {hex(hf_nvme_set_features_dword11)}')
                    self.logger.debug(f'hf_nvme_identify_dword12: {hex(hf_nvme_set_features_dword12)}')
                    self.logger.debug(f'hf_nvme_identify_dword13: {hex(hf_nvme_set_features_dword13)}')
                    self.logger.debug(f'hf_nvme_identify_dword14: {hex(hf_nvme_set_features_dword14)}')
                    self.logger.debug(f'hf_nvme_identify_dword15: {hex(hf_nvme_set_features_dword15)}')

                    # reply
                    reply = bytearray(24)
                    # PDU
                    # PDU type: capsule response
                    reply[0] = 0x05
                    # PDU specical flag
                    reply[1] = 0x00
                    # PDU header length
                    reply[2] = 0x18
                    # PDU data offset
                    reply[3] = 0x00
                    # packet length
                    reply[4:8] = b'\x18\x00\x00\x00'

                    # Cqe for cmd property set feature
                    # SQ head pointer, 看起来是上一个sq+1
                    reply[16:18] = b'\x07\x00'
                    self.logger.debug(f'send SQ head pointer: {reply[16:18]}')
                    # SQ id, 可以省略
                    reply[18:20] = b'\x00\x00'
                    # command id，与收包的command的id相同
                    reply[20:22] = struct.pack('<H', cmd_id)
                    self.logger.debug(f'send command id: {reply[20:22].hex()} recive cmd_id: {hex(cmd_id)}')
                    # status filed
                    reply[22:24] = b'\x00\x00'
                    self.logger.debug(f'len: {len(reply)} NVME_AQ_OPC_SET_FEATURE reply: {reply.hex()}')
                    try:
                        sock.sendall(reply)
                    except BrokenPipeError:
                        self.logger.debug('Client disconnected unexpectedly.')
                        break
                    self.logger.debug('reply NVME_AQ_OPC_SET_FEATURE request.')
                    self.logger.debug('--------------------------------------------------------\n')

                # NVME_AQ_OPC_ASYNC_EVE_REQ
                if opcode == 0x0c:
                    # TODO
                    self.logger.info("can't handle asycn event now. ")

                # NVME_AQ_OPC_KEEP_ALIVE
                if opcode == 0x18:
                    # TODO
                    self.logger.info("can't handle keep alive now.")

            if shutdown_now == 1:
                break

        except KeyboardInterrupt:
          self.logger.info("Received a ctrl+C interrupt. Exiting gracefully...")
          sock.close()
        sock.close()
        self.logger.info(f'Connection from {addr} closed.')

    def start_service(self):
        """Enable listening on the server side."""

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.discovery_addr, int(self.discovery_port)))
        # maximum number of connections
        s.listen(5)
        self.logger.info("Waiting for connection...")
        while True:
            sock, addr = s.accept()
            # create thread to handle nvme/tcp connection
            t = threading.Thread(target=self.nvmeof_tcp_connection, args=(sock, addr))
            t.start()

def main(args=None):
    # Set up root logger
    logging.basicConfig()
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

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

    # 参考 def restore(self, callbacks): 解析omap
    #bdevs = discovery_service._get_bdevs(my_omap_dict)
    #subsystems = discovery_service._get_subsystems(my_omap_dict)
    #namespaces = discovery_service._get_namespaces(my_omap_dict)
    #hosts = discovery_service._get_hosts(my_omap_dict)
    listeners = discovery_service._get_listeners(my_omap_dict)

    # setup listen service
    discovery_service.start_service()

    # TODO: omap update, watch/notify


if __name__ == "__main__":
    main()
