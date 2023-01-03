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
NVME_TCP_ICREQ = 0x0
NVME_TCP_ICRESP = 0x1
NVME_TCP_H2C_TERM = 0x2
NVME_TCP_C2H_TERM = 0x3
NVME_TCP_CMD = 0x4
NVME_TCP_RSP = 0x5
NVME_TCP_H2C_DATA = 0x6
NVME_TCP_C2H_DATA = 0x7
NVME_TCP_R2T = 0x9

# nvme tcp opcode
NVME_AQ_OPC_DELETE_SQ = 0x0
NVME_AQ_OPC_CREATE_SQ = 0x1
NVME_AQ_OPC_GET_LOG_PAGE = 0x2
NVME_AQ_OPC_DELETE_CQ = 0x4
NVME_AQ_OPC_CREATE_CQ = 0x5
NVME_AQ_OPC_IDENTIFY = 0x6
NVME_AQ_OPC_ABORT = 0x8
NVME_AQ_OPC_SET_FEATURES = 0x9
NVME_AQ_OPC_GET_FEATURES = 0xa
NVME_AQ_OPC_ASYNC_EVE_REQ = 0xc
NVME_AQ_OPC_NS_MGMT = 0xd
NVME_AQ_OPC_FW_COMMIT = 0x10
NVME_AQ_OPC_FW_IMG_DOWNLOAD = 0x11
NVME_AQ_OPC_NS_ATTACH = 0x15
NVME_AQ_OPC_KEEP_ALIVE = 0x18

# nvme tcp fabric command (special tcp opcode)
NVME_FABRIC_OPC = 0x7F

# nvme tcp fabric command type
NVME_FCTYPE_PROP_SET = 0x0
NVME_FCTYPE_CONNECT = 0x1
NVME_FCTYPE_PROP_GET = 0x4
NVME_FCTYPE_AUTH_SEND = 0x5
NVME_FCTYPE_AUTH_RECV = 0x6
NVME_FCTYPE_DISCONNECT = 0x8

# NVMe controller register space offsets
NVME_CTL_CAPABILITIES = 0x0
NVME_CTL_VERSION = 0x08
NVME_CTL_CONFIGURATION = 0x14
NVME_CTL_STATUS = 0x1c

# nvme tcp package length, refer: MTU = 1500 bytes
NVME_TCP_PDU_UNIT = 1024

# max SQ head pointer
SQ_HEAD_MAX = 128

lock = threading.Lock()

# global controller id
GLOBAL_CNLID = 0x1

# global generation counter
GLOBAL_GEN_CNT = 0x1

# TODO: Confirm the Python programming style,
# whether there is a requirement for a maximum number of bytes per line

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
        if self.discovery_addr == '' or self.discovery_port == '':
            assert 0
        self.logger.info(f"discovery addr: {self.discovery_addr} port: {self.discovery_port}")

    def _read_all(self) -> Dict[str, str]:
        """Reads OMAP and returns dict of all keys and values."""

        with rados.ReadOpCtx() as read_op:
            iter, _ = self.ioctx.get_omap_vals(read_op, "", "", -1)
            self.ioctx.operate_read_op(read_op, self.omap_name)
            omap_dict = dict(iter)
        return omap_dict

    def _get_vals(self, omap_dict, prefix):
        """Read bdevs/subsystems/namespaces/hosts/listeners from the OMAP dict."""

        vals = []
        for (key, val) in omap_dict.items():
            if key.startswith(prefix):
                val_text = val.decode('utf-8')
                js = json.loads(val_text)
                vals.append(js)
        return vals

    def reply_initialize(self, sock):
        """reply initialize request."""

        self.logger.debug("handle ICreq.")
        # reply
        reply = bytearray(128)
        # PDU: The meaning of the first 8 bytes of all PDUs is consistent with the following
        # PDU type
        reply[0] = NVME_TCP_ICRESP
        # PDU specical flag
        reply[1] = 0x00
        # PDU header length
        reply[2] = 0x80
        # PDU data offset
        reply[3] = 0x00
        # packet length
        reply[4:8] = b'\x80\x00\x00\x00'

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.error('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply initialize connection request.')

    def reply_fc_cmd_connect(self, sock, data, self_cnlid, sq_head_ptr):
        """reply connect request."""

        self.logger.debug("handle connect request.")
        hf_nvmeof_cmd_connect_rsvd1 = struct.unpack_from('<19B', data, 13)
        SIGL1 = struct.unpack_from('<QI4B', data, 32)
        address = SIGL1[0]
        length = SIGL1[1]
        reserved3 = SIGL1[2]
        descriptor_type = SIGL1[5]

        CMD2 = struct.unpack_from('<HHHBBI', data, 48)
        record_format = CMD2[0]
        queue_id = CMD2[1]
        submission_queue_size = CMD2[2]
        connect_attributes = CMD2[3]
        keep_alive_timeout = CMD2[5]

        nvmeof_connect_data_hostid = struct.unpack_from('<16B', data, 72)
        nvmeof_connect_data_cntlid = struct.unpack_from('<H', data, 88)[0]
        nvmeof_connect_data_subnqn = struct.unpack_from('<256B', data, 328)
        nvmeof_connect_data_hostnqn = struct.unpack_from('<256B', data, 584)

        reply = bytearray(24)
        reply[0] = NVME_TCP_RSP
        reply[1] = 0x00
        reply[2] = 0x18
        reply[3] = 0x00
        reply[4:8] = b'\x18\x00\x00\x00'

        # Cqe for cmd connect
        #controller id
        reply[8:10] = struct.pack('<H', self_cnlid)
        # SQ head pointer
        reply[16:18] = struct.pack('<H', sq_head_ptr)

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply connect request.')
        return (nvmeof_connect_data_hostid, nvmeof_connect_data_cntlid,
                nvmeof_connect_data_subnqn, nvmeof_connect_data_hostnqn)

    def reply_fc_cmd_prop_get(self, sock, data, sq_head_ptr,
                              cmd_id, shutdown_notification):
        """reply property get request."""

        self.logger.debug("handle property get request.")
        shutdown_now = 0
        nvmeof_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
        # property size = (attrib+1)x4, 0x1 means 8 bytes
        nvmeof_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
        nvmeof_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
        nvmeof_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]

        reply = bytearray(24)
        reply[0] = NVME_TCP_RSP
        reply[1] = 0x00
        reply[2] = 0x18
        reply[3] = 0x00
        reply[4:8] = b'\x18\x00\x00\x00'

        # reply different property data
        if nvmeof_prop_get_set_offset == NVME_CTL_CAPABILITIES:
            # controller capabilities
            # \x7f = maxinum queue entries support:128
            # \x01 contiguous queues required: true
            # \x1e timeout(to ready status): 1e(15000 ms), \x01=500ms
            # \x20 Q: command sets supportd: 1 (NVM IO command set)?
            reply[8:16] = b'\x7f\x00\x01\x1e\x20\x00\x00\x00'
        if nvmeof_prop_get_set_offset == NVME_CTL_CONFIGURATION:
            # won't run here，configuration discovery belongs to property set
            self.logger.error("don not support controller configuration in property get")
            assert 0
        if nvmeof_prop_get_set_offset == NVME_CTL_STATUS:
            if shutdown_notification == 0:
                # controller status: ready
                reply[8:16] = b'\x01\x00\x00\x00\x00\x00\x00\x00'
            else:
                # here shutdown_notification should be 0x1
                reply[8:16] = b'\x09\x00\x00\x00\x00\x00\x00\x00'
                shutdown_now = 1
        if nvmeof_prop_get_set_offset == NVME_CTL_VERSION:
            # nvme version 1.3, keep the same to spdk
            reply[8:16] = b'\x00\x03\x01\x00\x00\x00\x00\x00'
        reply[16:18] = struct.pack('<H', sq_head_ptr)
        # SQ id
        reply[18:20] = b'\x00\x00'
        reply[20:22] = struct.pack('<H', cmd_id)

        # status filed: successful completion
        reply[22:24] = b'\x00\x00'

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply property get request.')
        return shutdown_now

    def reply_fc_cmd_prop_set(self, sock, data, sq_head_ptr, cmd_id):
        """reply property set request."""

        self.logger.debug("handle property set request.")
        nvmeof_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
        nvmeof_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
        nvmeof_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
        nvmeof_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]
        controller_configuration = struct.unpack_from('<4B', data, 56)
        shutdown_notification = (controller_configuration[1] >> 6) & 0x3


        reply = bytearray(24)
        reply[0] = NVME_TCP_RSP
        reply[1] = 0x00
        reply[2] = 0x18
        reply[3] = 0x00
        reply[4:8] = b'\x18\x00\x00\x00'

        # Cqe for cmd property set
        # property set only support controller configruration request
        if nvmeof_prop_get_set_offset == NVME_CTL_CONFIGURATION:
            reply[16:18] = struct.pack('<H', sq_head_ptr)
            # SQ id
            reply[18:20] = b'\x00\x00'
            reply[20:22] = struct.pack('<H', cmd_id)
        else:
            self.logger.error("only support controller configruration in property set")
        # status filed
        reply[22:24] = b'\x00\x00'

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply property set request.')
        return shutdown_notification

    def reply_identify(self, sock, data, cmd_id,
                       self_cnlid, nvmeof_connect_data_subnqn):
        """reply identify request."""

        self.logger.debug("handle identify request.")
        nvme_nsid = struct.unpack_from('<I', data, 12)[0]
        nvme_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
        nvme_mptr = struct.unpack_from('<Q', data, 24)[0]
        nvme_sgl = struct.unpack_from('<16B', data, 32)
        nvme_sgl_desc_type = nvme_sgl[15] & 0xF0
        nvme_sgl_desc_sub_type = nvme_sgl[15] & 0x0F
        nvme_identify_dword10 = struct.unpack_from('<I', data, 48)[0]
        nvme_identify_dword11 = struct.unpack_from('<I', data, 52)[0]
        nvme_identify_dword12 = struct.unpack_from('<I', data, 56)[0]
        nvme_identify_dword13 = struct.unpack_from('<I', data, 60)[0]
        nvme_identify_dword14 = struct.unpack_from('<I', data, 64)[0]
        nvme_identify_dword15 = struct.unpack_from('<I', data, 68)[0]

        reply = bytearray(4120)
        reply[0] = NVME_TCP_C2H_DATA
        reply[1] = 0x0c
        reply[2] = 0x18
        reply[3] = 0x18
        reply[4:8] = b'\x18\x10\x00\x00'

        # NVMe/TCP Data PDU
        # command id
        reply[8:10] = struct.pack('<H', cmd_id)
        # transfer tag
        reply[10:12] = b'\x00\x00'
        # data offset
        reply[12:16] = b'\x00\x00\x00\x00'
        # data length
        reply[16:20] = b'\x00\x10\x00\x00'

        # NVM Express
        # firmware revision
        # Q: how to get? only know the firmware revision of a certain nvme device
        reply[88:96] = b'\x32\x33\x2e\x30\x35\x20\x20\x20'
        # maximum data transfer size
        reply[101] = 0x05
        # controller id
        reply[102:104] = struct.pack('<H', self_cnlid)
        # version: 1.3
        reply[104:108] = b'\x00\x03\x01\x00'
        # optional asynchronous events supported
        reply[116:120] = b'\x00\x00\x00\x80'
        # asynchronous events request limit
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
        # NVM Subsystem NVMe Qualified Name (SUBNQN): nqn.2014-08.org.nvmexpress.discovery
        for i in range(256):
            reply[792+i] = nvmeof_connect_data_subnqn[i]

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply identify request..')

    def reply_set_feature(self, sock, data, sq_head_ptr, cmd_id):
        """reply set feature request."""

        self.logger.debug("handle set feature request.")
        nvme_nsid = struct.unpack_from('<I', data, 12)[0]
        nvme_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
        nvme_mptr = struct.unpack_from('<Q', data, 24)[0]
        nvme_sgl = struct.unpack_from('<16B', data, 32)
        nvme_sgl_desc_type = nvme_sgl[15] & 0xF0
        nvme_sgl_desc_sub_type = nvme_sgl[15] & 0x0F
        nvme_set_features_dword10 = struct.unpack_from('<I', data, 48)[0]
        nvme_set_features_dword11 = struct.unpack_from('<I', data, 52)[0]
        nvme_set_features_dword12 = struct.unpack_from('<I', data, 56)[0]
        nvme_set_features_dword13 = struct.unpack_from('<I', data, 60)[0]
        nvme_set_features_dword14 = struct.unpack_from('<I', data, 64)[0]
        nvme_set_features_dword15 = struct.unpack_from('<I', data, 68)[0]

        reply = bytearray(24)
        reply[0] = NVME_TCP_RSP
        reply[1] = 0x00
        reply[2] = 0x18
        reply[3] = 0x00
        reply[4:8] = b'\x18\x00\x00\x00'

        # Cqe for cmd property set feature
        reply[16:18] = struct.pack('<H', sq_head_ptr)
        # SQ id
        reply[18:20] = b'\x00\x00'
        reply[20:22] = struct.pack('<H', cmd_id)
        # status filed
        reply[22:24] = b'\x00\x00'

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug('client disconnected unexpectedly.')
            raise
        self.logger.debug('reply set feature request.')

    def reply_get_log_page(self, sock, data, cmd_id,
                           self_gen_cnt, log_page, log_page_len):
        """reply get log page request."""

        self.logger.debug("handle get log page request.")
        my_omap_dict = self._read_all()
        listeners = self._get_vals(my_omap_dict, self.LISTENER_PREFIX)

        nvme_nsid = struct.unpack_from('<I', data, 12)[0]
        nvme_rsvd1 = struct.unpack_from('<Q', data, 16)[0]
        nvme_mptr = struct.unpack_from('<Q', data, 24)[0]
        nvme_sgl = struct.unpack_from('<16B', data, 32)
        nvme_sgl_desc_type = nvme_sgl[15] & 0xF0
        nvme_sgl_desc_sub_type = nvme_sgl[15] & 0x0F
        nvme_get_logpage_dword10 = struct.unpack_from('<I', data, 48)[0]
        # nvme_get_logpage_numd indicate the bytes when reply, rule: (values+1)*4
        nvme_get_logpage_numd = struct.unpack_from('<I', data, 50)[0]
        nvme_data_len = (nvme_get_logpage_numd + 1) * 4
        nvme_get_logpage_dword11 = struct.unpack_from('<I', data, 52)[0]
        # Logpage offset overlaps with dword13
        nvme_logpage_offset = struct.unpack_from('<Q', data, 56)[0]
        nvme_get_logpage_dword13 = struct.unpack_from('<I', data, 60)[0]
        nvme_get_logpage_dword14 = struct.unpack_from('<I', data, 64)[0]
        nvme_get_logpage_dword15 = struct.unpack_from('<I', data, 68)[0]
        get_logpage_lid = nvme_get_logpage_dword10 & 0xFF
        get_logpage_lsp = (nvme_get_logpage_dword10 >> 8) & 0x1F
        get_logpage_lsi = nvme_get_logpage_dword11 >> 16
        get_logpage_uid_idx = nvme_get_logpage_dword14 & 0x3F

        if get_logpage_lid != 0x70:
            self.logger.error(f'request type error. It is not discovery request.')
            return

        # Prepare all log page data segments
        if log_page_len == 0 and nvme_data_len > 16:
            log_page_len = 1024 * (len(listeners) + 1)
            log_page = bytearray(log_page_len)

            # the first 1024 bytes
            # generation counter
            log_page[0:8] = struct.pack('<Q', self_gen_cnt)
            # number of records
            log_page[8:16] = struct.pack('<Q', len(listeners))
            # record format
            log_page[16:18] = b'\x00\x00'

            # log entries
            log_entry_counter = 0
            while log_entry_counter < len(listeners):
                log_entry = bytearray(1024)
                self.logger.debug(f'log_entry len: {len(log_entry)}')
                # transport type: TCP
                log_entry[0] = 0x03
                # address family: AF_INET
                log_entry[1] = 0x01
                # Q: subsystem type: NVM system with IO controller(copy from spdk)?
                log_entry[2] = 0x02
                # transport requirement
                log_entry[3] = 0x02
                # port ID
                log_entry[4:6] = struct.pack('<H', log_entry_counter)
                # controller ID
                log_entry[6:8] = b'\xff\xff'
                # admin max SQ size
                log_entry[8:10] = b'\x80\x00'
                # transport service indentifier(TRSVCID)
                log_entry[32:64] = str(listeners[log_entry_counter]["trsvcid"]).encode().ljust(32, b'\x20')
                # NVM subsystem qualified name(nqn)
                log_entry[256:512] = str(listeners[log_entry_counter]["nqn"]).encode().ljust(256, b'\x00')
                # Transport address(traddr)
                log_entry[512:768] = str(listeners[log_entry_counter]["traddr"]).encode().ljust(256, b'\x20')

                log_page[1024*(log_entry_counter+1):1024*(log_entry_counter+2)] = log_entry
                log_entry_counter += 1
        else:
            self.logger.debug(f'in the process of sending log pages...')


        # reply based on the received get log page request packet(length)
        if nvme_data_len == 16:
            reply = bytearray(40)
            reply[0] = NVME_TCP_C2H_DATA
            reply[1] = 0x0c
            reply[2] = 0x18
            reply[3] = 0x18
            reply[4:8] = b'\x28\x00\x00\x00'

            # NVMe/TCP Data PDU
            reply[8:10] = struct.pack('<H', cmd_id)
            # transfer tag
            reply[10:12] = b'\x00\x00'
            # data offset
            reply[12:16] = b'\x00\x00\x00\x00'
            # data length
            reply[16:20] = b'\x10\x00\x00\x00'

            # NVMe Express
            # generation counter
            reply[24:32] = struct.pack('<Q', self_gen_cnt)
            # number of records
            reply[32:40] = struct.pack('<Q', len(listeners))
            try:
                sock.sendall(reply)
            except BrokenPipeError:
                self.logger.debug('client disconnected unexpectedly.')
                raise
        elif nvme_data_len > 16 and nvme_data_len % 1024 == 0:
            nvme_tcp_head_len = 24
            reply = bytearray(nvme_tcp_head_len)
            reply[0] = NVME_TCP_C2H_DATA
            reply[1] = 0x0c
            reply[2] = 0x18
            reply[3] = 0x18
            reply[4:8] = struct.pack('<I', nvme_tcp_head_len + nvme_data_len)

            reply[8:10] = struct.pack('<H', cmd_id)
            # transfer tag
            reply[10:12] = b'\x00\x00'
            # data offset
            reply[12:16] = b'\x00\x00\x00\x00'
            # data length
            reply[16:20] = struct.pack('<I', nvme_data_len)

            # NVMe Express
            reply = bytes(reply) + bytes(log_page[0:nvme_data_len])
            log_page = log_page[nvme_data_len:]
            log_page_len -= nvme_data_len

            try:
                sock.sendall(reply)
            except BrokenPipeError:
                self.logger.debug('client disconnected unexpectedly.')
                raise
        else:
            self.logger.error(f'lenghth error. It need be 16 or n*1024')
            # TODO: need to return err to stop connection
            return
        self.logger.debug('reply get log page request.')
        return log_page, log_page_len


    def nvmeof_tcp_connection(self, sock, addr):
        self.logger.info('Accept new connection from %s:%s...' % addr)
        # Some common variables
        nvmeof_connect_data_hostid = ()
        nvmeof_connect_data_cntlid = 0
        nvmeof_connect_data_subnqn = ()
        nvmeof_connect_data_hostnqn = ()
        sq_head_ptr = 0
        log_page = bytes()
        log_page_len = 0
        shutdown_notification = 0
        shutdown_now = 0
        global GLOBAL_CNLID
        global GLOBAL_GEN_CNT
        lock.acquire()
        self_cnlid = GLOBAL_CNLID
        self_gen_cnt = GLOBAL_GEN_CNT
        GLOBAL_CNLID += 1
        GLOBAL_GEN_CNT += 1
        lock.release()

        try:
          while True:
            sq_head_ptr += 1
            if sq_head_ptr > SQ_HEAD_MAX:
                sq_head_ptr = 1
            head = sock.recv(NVME_TCP_PDU_UNIT)
            if not head:
                time.sleep(0.01)
                continue

            PDU = struct.unpack_from('<BBBBI', head, 0)
            pdu_type = PDU[0]
            PSH_flag = PDU[1]
            PH_len = PDU[2]
            PH_off = PDU[3]
            package_len = PDU[4]

            self.logger.debug('\n')
            self.logger.debug('new message')
            self.logger.debug(f'pdu_type: {pdu_type}')
            self.logger.debug(f'PSH_flag: {PSH_flag}')
            self.logger.debug(f'PH_len: {PH_len}')
            self.logger.debug(f'PH_off: {PH_off}')
            self.logger.debug(f'package_len: {package_len}')

            # if the length exceeds one packet, continue to recive
            buffer = [head]
            if package_len > NVME_TCP_PDU_UNIT:
                i = package_len // NVME_TCP_PDU_UNIT
                if package_len % NVME_TCP_PDU_UNIT == 0:
                    i -= 1
                while i > 0:
                    d = sock.recv(NVME_TCP_PDU_UNIT)
                    if d:
                        buffer.append(d)
                        i -= 1
                    else:
                        break
            data = b''.join(buffer)

            # ICreq
            if pdu_type == NVME_TCP_ICREQ:
                self.reply_initialize(sock)

            # CMD
            if pdu_type == NVME_TCP_CMD:
                CMD1 = struct.unpack_from('<BBH', data, 8)
                opcode = CMD1[0]
                reserved = CMD1[1]
                cmd_id = CMD1[2]

                # fabric command
                if opcode == NVME_FABRIC_OPC:
                    fabric_cmd_type = struct.unpack_from('<B', data, 12)[0]
                    self.logger.debug(f'fabric_cmd_type: {hex(fabric_cmd_type)}')

                    if fabric_cmd_type == NVME_FCTYPE_CONNECT:
                        (nvmeof_connect_data_hostid, nvmeof_connect_data_cntlid,
                            nvmeof_connect_data_subnqn, nvmeof_connect_data_hostnqn) = \
                            self.reply_fc_cmd_connect(sock, data, self_cnlid, sq_head_ptr)

                    if fabric_cmd_type == NVME_FCTYPE_PROP_GET:
                        shutdown_now = self.reply_fc_cmd_prop_get(sock, data, sq_head_ptr,
                                                                  cmd_id, shutdown_notification)

                    if fabric_cmd_type == NVME_FCTYPE_PROP_SET:
                        shutdown_notification = self.reply_fc_cmd_prop_set(sock, data,
                                                                           sq_head_ptr, cmd_id)

                    # NVME_FCTYPE_AUTH_SEND
                    if fabric_cmd_type == NVME_FCTYPE_AUTH_SEND:
                        self.logger.debug("can't handle NVME_FCTYPE_AUTH_SEND request.")
                    # NVME_FCTYPE_AUTH_RECV
                    if fabric_cmd_type == NVME_FCTYPE_AUTH_RECV:
                        self.logger.debug("can't handle NVME_FCTYPE_AUTH_RECV request.")
                    # NVME_FCTYPE_DISCONNECT
                    if fabric_cmd_type == NVME_FCTYPE_DISCONNECT:
                        self.logger.debug("can't handle NVME_FCTYPE_DISCONNECT request.")

                # NVME_AQ_OPC_GET_LOG_PAGE
                if opcode == NVME_AQ_OPC_GET_LOG_PAGE:
                    log_page, log_page_len = self.reply_get_log_page(sock, data, cmd_id, self_gen_cnt,
                                                                     log_page, log_page_len)
 
                # NVME_AQ_OPC_IDENTIFY
                if opcode == NVME_AQ_OPC_IDENTIFY:
                    self.reply_identify(sock, data, cmd_id, self_cnlid,
                                        nvmeof_connect_data_subnqn)

                # NVME_AQ_OPC_SET_FEATURE
                if opcode == NVME_AQ_OPC_SET_FEATURES:
                    self.reply_set_feature(sock, data, sq_head_ptr, cmd_id)

                # NVME_AQ_OPC_ASYNC_EVE_REQ
                if opcode == NVME_AQ_OPC_ASYNC_EVE_REQ:
                    # TODO
                    self.logger.info("can't handle asycn event now. ")

                # NVME_AQ_OPC_KEEP_ALIVE
                if opcode == NVME_AQ_OPC_KEEP_ALIVE:
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
        # TODO: change to multi connection module
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

    # TODO: all raise and assert in connection need changing to close connection
    discovery_service = DiscoveryService(config)

    # setup listen service
    discovery_service.start_service()

    # TODO: omap update, watch/notify, send async 


if __name__ == "__main__":
    main()
