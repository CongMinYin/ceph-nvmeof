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

# NVMe tcp pdu type
NVME_TCP_ICREQ = 0x0
NVME_TCP_ICRESP = 0x1
NVME_TCP_H2C_TERM = 0x2
NVME_TCP_C2H_TERM = 0x3
NVME_TCP_CMD = 0x4
NVME_TCP_RSP = 0x5
NVME_TCP_H2C_DATA = 0x6
NVME_TCP_C2H_DATA = 0x7
NVME_TCP_R2T = 0x9

# NVMe tcp opcode
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

# NVMe tcp fabric command (special tcp opcode)
NVME_FABRIC_OPC = 0x7F

# NVMe tcp fabric command type
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


# NVM subsystem types
# Discovery type for NVM subsystem
NVMF_SUBTYPE_DISCOVERY = 0x1
# NVMe type for NVM subsystem
NVMF_SUBTYPE_NVME = 0x2

# NVMe over Fabrics transport types
NVMF_TRTYPE_RDMA = 0x1
NVMF_TRTYPE_FC = 0x2
NVMF_TRTYPE_TCP  = 0x3
# Intra-host transport (loopback)
NVMF_TRTYPE_INTRA_HOST = 0xfe

# Address family types
# IPv4 (AF_INET)
NVMF_ADRFAM_IPV4 = 0x1
# IPv6 (AF_INET6)
NVMF_ADRFAM_IPV6 = 0x2
# InfiniBand (AF_IB)
NVMF_ADRFAM_IB = 0x3
# Fibre Channel address family
NVMF_ADRFAM_FC = 0x4
# Intra-host transport (loopback)
NVMF_ADRFAM_INTRA_HOST	= 0xfe

# Transport requirement, secure channel requirements
# Connections shall be made over a fabric secure channel
NVMF_TREQ_SECURE_CHANNEL_NOT_SPECIFIED = 0x0
NVMF_TREQ_SECURE_CHANNEL_REQUIRED = 0x1
NVMF_TREQ_SECURE_CHANNEL_NOT_REQUIRED = 0x2

# NVMe tcp package length, refer: MTU = 1500 bytes
NVME_TCP_PDU_UNIT = 1024

# Max SQ head pointer
SQ_HEAD_MAX = 128

lock = threading.Lock()

# Global controller id
GLOBAL_CNLID = 0x1

# Global generation counter
GLOBAL_GEN_CNT = 0x1

class Pdu:
    def __init__(self):
        # PDU type
        self.type = bytearray(1)
        # PDU specical flag
        self.specical_flag = bytearray(1)
        # PDU header length
        self.header_length = bytearray(1)
        # PDU data offset
        self.data_offset = bytearray(1)
        # packet length
        self.packet_length = bytearray(4)

    def compose_reply(self):
        return self.type + self.specical_flag + self.header_length + \
               self.data_offset + self.packet_length

class ICResp:
    def __init__(self):
        # pdu version format
        self.version_format = bytearray(2)
        # controller Pdu data alignment
        self.data_alignment = bytearray(1)
        # digest types enabled
        self.digest_types = bytearray(1)
        # Maximum data capsules per r2t supported
        self.maximum_data_capsules = bytearray(4)

    def compose_reply(self):
        return self.version_format + self.data_alignment + \
               self.digest_types + self.maximum_data_capsules

class CqeConnect:
    def __init__(self):
        # controller id
        self.controller_id = bytearray(2)
        # authentication required
        self.authentication = bytearray(2)
        self.reserved = bytearray(4)
        # SQ head pointer
        self.sq_head_ptr = bytearray(2)
        # SQ identifier
        self.sq_id = bytearray(2)
        # command identifier
        self.cmd_id = bytearray(2)
        # status field: 0 = successful completion
        self.status = bytearray(2)

    def compose_reply(self):
        return self.controller_id + self.authentication + self.reserved + \
               self.sq_head_ptr + self.sq_id + self.cmd_id + self.status

class CqePropertyGetSet:
    def __init__(self):
        # property data for property get, reserved for property set
        self.property_data = bytearray(8)
        # SQ head pointer
        self.sq_head_ptr = bytearray(2)
        # SQ identifier
        self.sq_id = bytearray(2)
        # command identifier
        self.cmd_id = bytearray(2)
        # status field
        self.status = bytearray(2)
    def compose_reply(self):
        return self.property_data + self.sq_head_ptr + self.sq_id + \
               self.cmd_id + self.status

class NVMeTcpDataPdu:
    def __init__(self):
        # command id
        self.cmd_id = bytearray(2)
        # transfer tag
        self.transfer_tag = bytearray(2)
        # data offset
        self.data_offset = bytearray(4)
        # data length
        self.data_length = bytearray(4)
        # reserved
        self.reserved = bytearray(4)

    def compose_reply(self):
        return self.cmd_id + self.transfer_tag + \
               self.data_offset + self.data_length + self.reserved

class NVMeIdentify:
    def __init__(self):
        # skip some fields, include VID, SSVID, SN, MN
        self.todo_fields1 = bytearray(64)
        # firmware revision
        self.firmware_revision = bytearray(8)
        # RAB, IEEE, CMIC
        self.todo_fields2 = bytearray(5)
        # maximum data transfer size
        self.mdts = bytearray(1)
        # controller id
        self.controller_id = bytearray(2)
        # version
        self.version = bytearray(4)
        # RTD3R, RTD3E
        self.todo_fields3 = bytearray(8)
        # optional asynchronous events supported
        self.oaes = bytearray(4)
        # CTRATT, RRLS, CNTRLTYPE, FGUID, NVMe Management Interface, OACS, ACL
        self.todo_fields4 = bytearray(163)
        # asynchronous events request limit
        self.aerl = bytearray(1)
        # firmware updates
        self.firmware_updates = bytearray(1)
        # log page attributes
        self.lpa = bytearray(1)
        # error log page entries(ELPE)
        self.elpe = bytearray(1)
        # NPSS, AVSCC, APSTA, WCTEMP, CCTEMP, MTFA, HMPRE, HMIN, TNVMCAP...
        self.todo_fields5 = bytearray(251)
        # maximum outstanding commands
        self.maxcmd = bytearray(2)
        # number of namespace, optional NVM command support
        self.todo_fields6 = bytearray(6)
        # fused operation support
        self.fused_operation = bytearray(2)
        # FNA, VWC, AWUN, AWUPF, NVSCC, NWPC
        self.todo_fields7 = bytearray(8)
        # atomic compare & write unit
        self.acwu = bytearray(2)
        self.reserved1 = bytearray(2)
        # SGL support
        self.sgls = bytearray(4)
        # maxinum number of allowed namespaces
        self.mnan = bytearray(4)
        self.reserved2 = bytearray(224)
        # NVM subsystem NVMe qualified name
        self.subnqn = bytearray(256)
        self.reserved3 = bytearray(768)
        # NVMeOF attributes
        self.nvmeof_attributes = bytearray(256)
        # power state attributes
        self.power_state_attributes = bytearray(1024)
        # vendor specific
        self.vendor_specific = bytearray(1024)

    def compose_reply(self):
        return self.todo_fields1 + self.firmware_revision + \
               self.todo_fields2 + self.mdts + self.controller_id + \
               self.version + self.todo_fields3 + self.oaes + \
               self.todo_fields4 + self.aerl + self.firmware_updates + \
               self.lpa + self.elpe + self.todo_fields5 + self.maxcmd + \
               self.todo_fields6 + self.fused_operation + self.todo_fields7 + \
               self.acwu + self.reserved1 + self.sgls + self.mnan +\
               self.reserved2 + self.subnqn + self.reserved3 + \
               self.nvmeof_attributes + self.power_state_attributes + \
               self.vendor_specific


class CqeSetFeature:
    def __init__(self):
        # DWORD0
        self.dword0 = bytearray(4)
        # DWORD1
        self.dword1 = bytearray(4)
        # SQ head pointer
        self.sq_head_ptr = bytearray(2)
        # SQ identifier
        self.sq_id = bytearray(2)
        # command identifier
        self.cmd_id = bytearray(2)
        # status field
        self.status = bytearray(2)

    def compose_reply(self):
        return self.dword0 + self.dword1 + self.sq_head_ptr + \
               self.sq_id + self.cmd_id + self.status

class NVMeGetLogPage:
    def __init__(self):
        # generation counter
        self.genctr = bytearray(8)
        # number of records
        self.numrec = bytearray(8)

        #record format
        self.recfmt = bytearray(2)
        self.reserved = bytearray(1006)

    def compose_short_reply(self):
        return self.genctr + self.numrec

    def compose_data_reply(self):
        return self.genctr + self.numrec + self.recfmt + self.reserved

class DiscoveryLogEntry:
    def __init__(self):
        # transport type
        self.trtype = bytearray(1)
        # adress family
        self.adrfam = bytearray(1)
        # subsystem type
        self.subtype = bytearray(1)
        # transport requirement
        self.treq = bytearray(1)
        # port ID
        self.port_id = bytearray(2)
        # controller ID
        self.controller_id = bytearray(2)
        # admin max SQ size
        self.asqsz = bytearray(2)
        self.reserved1 = bytearray(22)
        # transport service indentifier
        self.trsvcid = bytearray(32)
        self.reserved2 = bytearray(192)
        # NVM subsystem qualified name
        self.subnqn = bytearray(256)
        # Transport address(TRADDR)
        self.traddr = bytearray(256)
        # Transport specific address subtype
        self.tsas = bytearray(256)

    def compose_reply(self):
        return self.trtype + self.adrfam + self.subtype + \
               self.treq + self.port_id + self.controller_id + \
               self.asqsz + self.reserved1 + self.trsvcid + \
               self.reserved2 + self.subnqn + self.traddr + self.tsas

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
        self.logger.setLevel(level=logging.DEBUG)

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
            self.logger.error(f"discovery addr/port are empty.")
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
        """Reply initialize request."""

        self.logger.debug("handle ICreq.")

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_ICRESP])
        pdu_reply.header_length = b'\x80'
        pdu_reply.packet_length = b'\x80\x00\x00\x00'

        icresp_reply = ICResp()
        # Maximum data capsules per r2t supported: 131072
        icresp_reply.maximum_data_capsules = b'\x00\x00\x02\x00'

        reply = pdu_reply.compose_reply() + icresp_reply.compose_reply() + bytearray(112)

        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.error("client disconnected unexpectedly.")
            return -1
        self.logger.debug("reply initialize connection request.")
        return 0

    def reply_fc_cmd_connect(self, sock, data, self_cnlid, sq_head_ptr):
        """Reply connect request."""

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

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_RSP])
        pdu_reply.header_length = b'\x18'
        pdu_reply.packet_length = b'\x18\x00\x00\x00'

        # Cqe for cmd connect
        connect_reply = CqeConnect()
        connect_reply.controller_id = struct.pack('<H', self_cnlid)
        connect_reply.sq_head_ptr = struct.pack('<H', sq_head_ptr)

        reply = pdu_reply.compose_reply() + connect_reply.compose_reply()
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug("client disconnected unexpectedly.")
            return -1, 0, 0, 0, 0
        self.logger.debug("reply connect request.")
        return 0, nvmeof_connect_data_hostid, nvmeof_connect_data_cntlid, \
               nvmeof_connect_data_subnqn, nvmeof_connect_data_hostnqn

    def reply_fc_cmd_prop_get(self, sock, data, sq_head_ptr,
                              cmd_id, shutdown_notification):
        """Reply property get request."""

        self.logger.debug("handle property get request.")
        shutdown_now = 0
        nvmeof_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
        # property size = (attrib+1)x4, 0x1 means 8 bytes
        nvmeof_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
        nvmeof_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
        nvmeof_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_RSP])
        pdu_reply.header_length = b'\x18'
        pdu_reply.packet_length = b'\x18\x00\x00\x00'

        # reply different property data
        property_get = CqePropertyGetSet()
        if nvmeof_prop_get_set_offset == NVME_CTL_CAPABILITIES:
            # controller capabilities
            # \x7f = maxinum queue entries support:128
            # \x01 contiguous queues required: true
            # \x1e timeout(to ready status): 1e(15000 ms), \x01=500ms
            # \x20 Q: command sets supportd: 1 (NVM IO command set)?
            property_get.property_data = b'\x7f\x00\x01\x1e\x20\x00\x00\x00'
        if nvmeof_prop_get_set_offset == NVME_CTL_CONFIGURATION:
            # won't run here，configuration discovery belongs to property set
            self.logger.error("do not support controller configuration in property get")
            return -1, 0
        if nvmeof_prop_get_set_offset == NVME_CTL_STATUS:
            if shutdown_notification == 0:
                # controller status: ready
                property_get.property_data = b'\x01\x00\x00\x00\x00\x00\x00\x00'
            else:
                # here shutdown_notification should be 0x1
                property_get.property_data = b'\x09\x00\x00\x00\x00\x00\x00\x00'
                shutdown_now = 1
        if nvmeof_prop_get_set_offset == NVME_CTL_VERSION:
            # Q: nvme version: 1.3?
            property_get.property_data = b'\x00\x03\x01\x00\x00\x00\x00\x00'
        property_get.sq_head_ptr = struct.pack('<H', sq_head_ptr)
        property_get.cmd_id = struct.pack('<H', cmd_id)

        reply = pdu_reply.compose_reply() + property_get.compose_reply()
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug("client disconnected unexpectedly.")
            return -1, 0
        self.logger.debug("reply property get request.")
        return 0, shutdown_now

    def reply_fc_cmd_prop_set(self, sock, data, sq_head_ptr, cmd_id):
        """Reply property set request."""

        self.logger.debug("handle property set request.")
        nvmeof_prop_get_set_rsvd0 = struct.unpack_from('<35B', data, 13)
        nvmeof_prop_get_set_attrib = struct.unpack_from('<1B', data, 48)[0]
        nvmeof_prop_get_set_rsvd1 = struct.unpack_from('<3B', data, 49)
        nvmeof_prop_get_set_offset = struct.unpack_from('<I', data, 52)[0]
        controller_configuration = struct.unpack_from('<4B', data, 56)
        shutdown_notification = (controller_configuration[1] >> 6) & 0x3

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_RSP])
        pdu_reply.header_length = b'\x18'
        pdu_reply.packet_length = b'\x18\x00\x00\x00'

        # Cqe for cmd property set
        # property set only support controller configruration request
        property_set = CqePropertyGetSet()
        if nvmeof_prop_get_set_offset == NVME_CTL_CONFIGURATION:
            property_set.sq_head_ptr = struct.pack('<H', sq_head_ptr)
            property_set.cmd_id = struct.pack('<H', cmd_id)
        else:
            self.logger.error("only support controller configruration in property set")

        reply = pdu_reply.compose_reply() + property_set.compose_reply()
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug("client disconnected unexpectedly.")
            return -1, 0
        self.logger.debug("reply property set request.")
        return 0, shutdown_notification

    def reply_identify(self, sock, data, cmd_id,
                       self_cnlid, nvmeof_connect_data_subnqn):
        """Reply identify request."""

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

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_C2H_DATA])
        # 0x0c == 0b1100, means pdu data last: set, pdu data success: set
        pdu_reply.specical_flag = b'\x0c'
        pdu_reply.header_length = b'\x18'
        pdu_reply.data_offset = b'\x18'
        pdu_reply.packet_length = b'\x18\x10\x00\x00'

        nvme_tcp_data_pdu = NVMeTcpDataPdu()
        # NVMe/TCP Data PDU
        nvme_tcp_data_pdu.cmd_id = struct.pack('<H', cmd_id)
        nvme_tcp_data_pdu.data_length = b'\x00\x10\x00\x00'

        # NVM Express
        identify_reply = NVMeIdentify()
        # Q: version: 0.01
        identify_reply.firmware_revision = b'\x30\x30\x2e\x30\x31\x20\x20\x20'
        # maximum data transfer size: 2^5=32 pages
        identify_reply.mdts = b'\x05'
        identify_reply.controller_id = struct.pack('<H', self_cnlid)
        # version: 1.3
        identify_reply.version = b'\x00\x03\x01\x00'
        identify_reply.oaes = b'\x00\x00\x00\x80'
        # asynchronous events request limit: 4 events
        identify_reply.aerl = b'\x03'
        # log page attributes:True
        identify_reply.lpa = b'\x04'
        # error log page entries:128 entries
        identify_reply.elpe = b'\x7f'
        identify_reply.maxcmd = b'\x80\x00'
        identify_reply.fused_operation = b'\x01\x00'
        # atomic compare & write unit: 4096 bytes
        identify_reply.acwu = b'\x01\x00'
        identify_reply.sgls = b'\x05\x00\x10\x00'
        for i in range(256):
            identify_reply.subnqn[i] = nvmeof_connect_data_subnqn[i]

        reply = pdu_reply.compose_reply() + nvme_tcp_data_pdu.compose_reply() + \
                identify_reply.compose_reply()
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug("client disconnected unexpectedly.")
            return -1
        self.logger.debug("reply identify request.")
        return 0

    def reply_set_feature(self, sock, data, sq_head_ptr, cmd_id):
        """Reply set feature request."""

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

        pdu_reply = Pdu()
        pdu_reply.type = bytearray([NVME_TCP_RSP])
        pdu_reply.header_length = b'\x18'
        pdu_reply.packet_length = b'\x18\x00\x00\x00'

        # Cqe for cmd property set feature
        set_feature_reply = CqeSetFeature()
        set_feature_reply.sq_head_ptr = struct.pack('<H', sq_head_ptr)
        set_feature_reply.cmd_id = struct.pack('<H', cmd_id)

        reply = pdu_reply.compose_reply() + set_feature_reply.compose_reply()
        try:
            sock.sendall(reply)
        except BrokenPipeError:
            self.logger.debug("client disconnected unexpectedly.")
            return -1
        self.logger.debug("reply set feature request.")
        return 0

    def reply_get_log_page(self, sock, data, cmd_id,
                           self_gen_cnt, log_page, log_page_len):
        """Reply get log page request."""

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
            self.logger.error(f"request type error, not discovery request.")
            return -1, 0, 0

        # Prepare all log page data segments
        # TODO: Filter log entries based on access permissions
        if log_page_len == 0 and nvme_data_len > 16:
            log_page_len = 1024 * (len(listeners) + 1)
            log_page = bytearray(log_page_len)

            nvme_get_log_page_reply = NVMeGetLogPage()
            nvme_get_log_page_reply.genctr = struct.pack('<Q', self_gen_cnt)
            nvme_get_log_page_reply.numrec = struct.pack('<Q', len(listeners))
            log_page[0:1024] = nvme_get_log_page_reply.compose_data_reply()

            # log entries
            log_entry_counter = 0
            while log_entry_counter < len(listeners):
                log_entry = DiscoveryLogEntry()
                trtype = 0
                adrfam = 0
                if listeners[log_entry_counter]["trtype"] == "TCP":
                    trtype = NVMF_TRTYPE_TCP
                else:
                    # TODO
                    self.logger.debug(f"not implement other transport type")
                if listeners[log_entry_counter]["adrfam"] == "ipv4":
                    adrfam = NVMF_ADRFAM_IPV4
                else:
                    # TODO
                    self.logger.debug(f"not implement other adress family")
                log_entry.trtype = bytearray([trtype])
                log_entry.adrfam = bytearray([adrfam])
                # Q: NVMF_SUBTYPE_NVME or NVMF_SUBTYPE_DISCOVERY, not store in omap
                log_entry.subtype = bytearray([NVMF_SUBTYPE_NVME])
                log_entry.treq = bytearray([NVMF_TREQ_SECURE_CHANNEL_NOT_REQUIRED])
                # port ID
                log_entry.port_id = struct.pack('<H', log_entry_counter)
                # controller ID
                log_entry.controller_id = b'\xff\xff'
                # admin max SQ size
                log_entry.asqsz = b'\x80\x00'
                # transport service indentifier
                log_entry.trsvcid = str(listeners[log_entry_counter]["trsvcid"]).encode().ljust(32, b'\x20')
                # NVM subsystem qualified name
                log_entry.subnqn = str(listeners[log_entry_counter]["nqn"]).encode().ljust(256, b'\x00')
                # Transport address
                log_entry.traddr = str(listeners[log_entry_counter]["traddr"]).encode().ljust(256, b'\x20')

                log_page[1024*(log_entry_counter+1):1024*(log_entry_counter+2)] = log_entry.compose_reply()
                log_entry_counter += 1
        else:
            self.logger.debug(f"in the process of sending log pages...")

        # reply based on the received get log page request packet(length)
        if nvme_data_len == 16:
            pdu_reply = Pdu()
            pdu_reply.type = bytearray([NVME_TCP_C2H_DATA])
            pdu_reply.specical_flag = b'\x0c'
            pdu_reply.header_length = b'\x18'
            pdu_reply.data_offset = b'\x18'
            pdu_reply.packet_length = b'\x28\x00\x00\x00'

            # NVMe/TCP Data PDU
            nvme_tcp_data_pdu = NVMeTcpDataPdu()
            nvme_tcp_data_pdu.cmd_id = struct.pack('<H', cmd_id)
            nvme_tcp_data_pdu.data_length = b'\x10\x00\x00\x00'

            # NVM Express
            nvme_get_log_page_reply = NVMeGetLogPage()
            nvme_get_log_page_reply.genctr = struct.pack('<Q', self_gen_cnt)
            nvme_get_log_page_reply.numrec = struct.pack('<Q', len(listeners))

            reply = pdu_reply.compose_reply() + nvme_tcp_data_pdu.compose_reply() + \
                    nvme_get_log_page_reply.compose_short_reply()
            try:
                sock.sendall(reply)
            except BrokenPipeError:
                self.logger.debug("client disconnected unexpectedly.")
                return -1, 0, 0
        elif nvme_data_len > 16 and nvme_data_len % 1024 == 0:
            # class Pdu and NVMeTcpDataPdu
            pdu_and_nvme_pdu_len = 8 + 16

            pdu_reply = Pdu()
            pdu_reply.type = bytearray([NVME_TCP_C2H_DATA])
            pdu_reply.specical_flag = b'\x0c'
            pdu_reply.header_length = b'\x18'
            pdu_reply.data_offset = b'\x18'
            pdu_reply.packet_length = struct.pack('<I', pdu_and_nvme_pdu_len + nvme_data_len)

            # NVMe/TCP Data PDU
            nvme_tcp_data_pdu = NVMeTcpDataPdu()
            nvme_tcp_data_pdu.cmd_id = struct.pack('<H', cmd_id)
            nvme_tcp_data_pdu.data_length = struct.pack('<I', nvme_data_len)

            # NVM Express
            reply = pdu_reply.compose_reply() + nvme_tcp_data_pdu.compose_reply() + \
                    log_page[0:nvme_data_len]
            log_page = log_page[nvme_data_len:]
            log_page_len -= nvme_data_len
            try:
                sock.sendall(reply)
            except BrokenPipeError:
                self.logger.debug("client disconnected unexpectedly.")
                return -1, 0, 0
        else:
            self.logger.error(f"lenghth error. It need be 16 or n*1024")
            return -1, 0, 0
        self.logger.debug("reply get log page request.")
        return 0, log_page, log_page_len


    def nvmeof_tcp_connection(self, sock, addr):
        self.logger.info(f"Accept new connection from {addr}")
        # Some common variables
        nvmeof_connect_data_hostid = ()
        nvmeof_connect_data_cntlid = 0
        nvmeof_connect_data_subnqn = ()
        nvmeof_connect_data_hostnqn = ()
        err = 0
        sq_head_ptr = 0
        log_page = bytearray()
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
                err = self.reply_initialize(sock)

            # CMD
            if pdu_type == NVME_TCP_CMD:
                CMD1 = struct.unpack_from('<BBH', data, 8)
                opcode = CMD1[0]
                reserved = CMD1[1]
                cmd_id = CMD1[2]

                # fabric command
                if opcode == NVME_FABRIC_OPC:
                    fabric_cmd_type = struct.unpack_from('<B', data, 12)[0]

                    if fabric_cmd_type == NVME_FCTYPE_CONNECT:
                        (err, nvmeof_connect_data_hostid, nvmeof_connect_data_cntlid,
                            nvmeof_connect_data_subnqn, nvmeof_connect_data_hostnqn) = \
                            self.reply_fc_cmd_connect(sock, data, self_cnlid, sq_head_ptr)

                    if fabric_cmd_type == NVME_FCTYPE_PROP_GET:
                        err, shutdown_now = self.reply_fc_cmd_prop_get(sock, data, sq_head_ptr,
                                                                       cmd_id, shutdown_notification)

                    if fabric_cmd_type == NVME_FCTYPE_PROP_SET:
                        err, shutdown_notification = self.reply_fc_cmd_prop_set(sock, data,
                                                                                sq_head_ptr, cmd_id)

                    if fabric_cmd_type == NVME_FCTYPE_AUTH_SEND:
                        self.logger.error("can't handle NVME_FCTYPE_AUTH_SEND request.")
                    if fabric_cmd_type == NVME_FCTYPE_AUTH_RECV:
                        self.logger.error("can't handle NVME_FCTYPE_AUTH_RECV request.")
                    if fabric_cmd_type == NVME_FCTYPE_DISCONNECT:
                        self.logger.error("can't handle NVME_FCTYPE_DISCONNECT request.")

                if opcode == NVME_AQ_OPC_GET_LOG_PAGE:
                    err, log_page, log_page_len = self.reply_get_log_page(sock, data, cmd_id, self_gen_cnt,
                                                                          log_page, log_page_len)

                if opcode == NVME_AQ_OPC_IDENTIFY:
                    err, self.reply_identify(sock, data, cmd_id, self_cnlid,
                                             nvmeof_connect_data_subnqn)

                if opcode == NVME_AQ_OPC_SET_FEATURES:
                    err = self.reply_set_feature(sock, data, sq_head_ptr, cmd_id)

                if opcode == NVME_AQ_OPC_ASYNC_EVE_REQ:
                    # TODO
                    self.logger.error("can't handle asycn event now. ")

                if opcode == NVME_AQ_OPC_KEEP_ALIVE:
                    # TODO
                    self.logger.error("can't handle keep alive now.")

            if shutdown_now == 1:
                break
            if err == -1:
                self.logger.error("error, close connection.")
                break
        sock.close()
        self.logger.info(f"connection from {addr} closed.")

    def start_service(self):
        """Enable listening on the server side."""

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.discovery_addr, int(self.discovery_port)))
        # maximum number of connections
        s.listen(5)
        self.logger.info("waiting for connection...")
        # TODO: change to multi connection module
        try:
          while True:
            sock, addr = s.accept()
            # create thread to handle nvme/tcp connection
            t = threading.Thread(target=self.nvmeof_tcp_connection, args=(sock, addr))
            t.start()
        except KeyboardInterrupt:
          self.logger.info("received a ctrl+C interrupt. exiting...")

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

    config = GatewayConfig(args.config)
    discovery_service = DiscoveryService(config)
    discovery_service.start_service()

    # TODO: omap update, watch/notify, send async 


if __name__ == "__main__":
    main()
