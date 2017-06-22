#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pty
import re
import time
import Queue
import threading

from lib.etrx3x_at_cmds import ETRX3xATCommand
from sgcon.lib.sgcon_validators import validate_node_identifier
from sgcon.lib.zigbee import ZigBeeNetwork


class ETRX3xSimulatorException(Exception, object):
    """docstring for ETRX3xSimulatorException."""
    def __init__(self, msg):
        super(ETRX3xSimulatorException, self).__init__()
        self.msg = msg

    def __str__(self):
        return "ETRX3xSimulatorException: {}".format(self.msg)


class ETRX3xSimulator(object):
    """docstring for ETRX3xSimulator."""
    def __init__(
            self,
            zbnet_list,
            local_node_eui,
            local_pan_eid,
            coo_etrx3x_sregs=None,
            router_etrx3x_sregs=None,
            sed_etrx3x_sregs=None,
            med_etrx3x_sregs=None,
            zed_etrx3x_sregs=None):
        super(ETRX3xSimulator, self).__init__()
        # AT commands protocol class
        self.etrx3x_at = ETRX3xATCommand()

        self.zbnet_list = zbnet_list
        self.local_node_eui = local_node_eui
        self.local_pan_eid = local_pan_eid

        if(coo_etrx3x_sregs is not None):
            try:
                self._validate_etrx3x_config(coo_etrx3x_sregs)
                self.coo_etrx3x_sregs = coo_etrx3x_sregs
            except ETRX3xSimulatorException as err:
                print(err)
                return

        if(router_etrx3x_sregs is not None):
            try:
                self._validate_etrx3x_config(router_etrx3x_sregs)
                self.router_etrx3x_sregs = router_etrx3x_sregs
            except ETRX3xSimulatorException as err:
                print(err)
                return

        if(sed_etrx3x_sregs is not None):
            try:
                self._validate_etrx3x_config(sed_etrx3x_sregs)
                self.sed_etrx3x_sregs = sed_etrx3x_sregs
            except ETRX3xSimulatorException as err:
                print(err)
                return

        if(med_etrx3x_sregs is not None):
            try:
                self._validate_etrx3x_config(med_etrx3x_sregs)
                self.med_etrx3x_sregs = med_etrx3x_sregs
            except ETRX3xSimulatorException as err:
                print(err)
                return

        if(zed_etrx3x_sregs is not None):
            try:
                self._validate_etrx3x_config(zed_etrx3x_sregs)
                self.zed_etrx3x_sregs = zed_etrx3x_sregs
            except ETRX3xSimulatorException as err:
                print(err)
                return

        self.zb_networks = {}
        try:
            self._load_zb_networks(
                zbnet_list, self.local_node_eui, self.local_pan_eid)
        except ETRX3xSimulatorException as err:
            print(err)
            return

        self.local_zb_network = self.zb_networks[self.local_pan_eid]
        self.local_node = self.local_zb_network.get_local_node()
        self.local_pan = self.local_zb_network.get_local_pan()

        # Simulation control
        self.main_loop = False
        self.echo_enabled = False

        # AT data
        self.seq_counter = 0

        self.write_queue = Queue.Queue()
        self.write_thread = None

        self.local_node_atable = [
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"},
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"},
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"},
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"},
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"},
            {"active": False, "node_id": "0000",
                "node_eui": "000D6F0000BA19DB"},
            {"active": False, "node_id": "FFFF",
                "node_eui": "FFFFFFFFFFFFFFFF"}
        ]

        self.local_node_ntable = [
            {"type": "COO", "node_eui": "000D6F0000BA19DB",
                "node_id": "0000", "signal": 255},
            {"type": "FFD", "node_eui": "000D6F0002544E9D",
                "node_id": "AB76", "signal": 255},
            {"type": "FFD", "node_eui": "000D6F00023EC0D5",
                "node_id": "D2F8", "signal": 255},
            {"type": "FFD", "node_eui": "000D6F00027D2566",
                "node_id": "B5B4", "signal": 253},
            {"type": "FFD", "node_eui": "000D6F000B47CC5F",
                "node_id": "C595", "signal": 255},
        ]

    def _validate_etrx3x_config(self, config_dict):
        try:
            for sreg in config_dict:
                self.etrx3x_at.validate_sregister_number(sreg)
                self.etrx3x_at.validate_sregister_value(
                    sreg, config_dict[sreg])
        except ValueError as err:
            raise ETRX3xSimulatorException(err)

    def _load_zb_networks(self, zbnet_list, local_node_eui, local_pan_eid):
        for zbnet in zbnet_list:
            net = ZigBeeNetwork()

            pan = zbnet["pan"]
            pan_channel = pan["channel"]
            pan_id = pan["id"]
            pan_eid = pan["eid"]
            pan_netkey = pan["netkey"]
            pan_linkkey = pan["linkkey"]

            zbpan = net.add_pan(
                pan_channel, "-07", pan_id, pan_eid, "02", True)

            if(pan_eid == local_pan_eid):
                net.set_local_pan(zbpan)

            for node in zbnet["nodes"]:
                node_id = node["id"]
                node_eui = node["eui"]
                node_type = node["type"]
                node_parent_id = node["parent_id"]
                node_sregs = node["sregs"]

                node = net.add_node(
                    node_eui,
                    node_id=node_id,
                    node_type=node_type)

                if(node_type == "COO"):
                    regs = self.coo_etrx3x_sregs
                elif(node_type == "FFD"):
                    regs = self.router_etrx3x_sregs
                elif(node_type == "SED"):
                    regs = self.sed_etrx3x_sregs
                elif(node_type == "MED"):
                    regs = self.med_etrx3x_sregs
                elif(node_type == "ZED"):
                    regs = self.zed_etrx3x_sregs
                else:
                    raise ETRX3xSimulatorException(
                        "_load_zb_networks: invalid node type {!r}".format(
                            node_type))

                # Set nodes sregisters values
                for reg in regs:
                    # TODO(rubens): set pan channel mask in hex format
                    # regs["00"] = pan_channel
                    if(reg == "03"):
                        node.add_sregister(reg, pan_eid)
                    elif(reg == "04"):
                        node.add_sregister(reg, node_eui)
                    elif(reg == "05"):
                        node.add_sregister(reg, node_id)
                    # TODO(rubens): set node parent eui
                    # regs["06"] = node_parent_eui
                    elif(reg == "07"):
                        node.add_sregister(reg, node_parent_id)
                    elif(reg == "08"):
                        node.add_sregister(reg, pan_netkey)
                    elif(reg == "09"):
                        node.add_sregister(reg, pan_linkkey)
                    else:
                        node.add_sregister(reg, regs[reg])

                # Set Address Table
                for i in range(0, 7):
                    node.add_address_entry("N", "FFFF", "FFFFFFFFFFFFFFFF")

                if(node_eui == local_node_eui):
                    net.set_local_node(node)

            for link in zbnet["links"]:
                link_id_src = link["id_src"]
                link_id_dst = link["id_dst"]
                link_quality = link["lqi"]

                node_src = net.get_node(link_id_src)
                node_src.add_neighbour(
                    link_id_src, link_id_dst, lqi=link_quality)

                node_dst = net.get_node(link_id_dst)
                node_dst.add_neighbour(
                    link_id_dst, link_id_src, lqi=link_quality)

            self.zb_networks[pan_eid] = net

    def get_seq_number(self):
        seq_number = self.seq_counter
        self.seq_counter = (self.seq_counter + 1) % 256
        return seq_number

    def _write_thread_function(self):
        while(self.main_loop is True):
            try:
                message = self.write_queue.get(True, 1)

                os.write(self.master, message)
            except Queue.Empty:
                pass

    def write_serial(self, message):
        self.write_queue.put(message)

    def write_async_message(self, message, delay=0.1):
        # print(
        #     "Starting thread to send async response {!r} in"
        #     " {} seconds".format(message, delay))

        self.write_thread = threading.Thread(
            target=self._write_async_message, args=(message, delay))
        self.write_thread.setDaemon(True)
        self.write_thread.start()

    def _write_async_message(self, message, delay):
        time.sleep(delay)
        os.write(self.master, message)

    def start(self):
        self.master, self.slave = pty.openpty()

        slave_name = os.ttyname(self.slave)
        master_name = os.ttyname(self.master)
        print("Slave : {}".format(slave_name))
        print("Master: {}".format(master_name))

        self.main_loop = True

        print("Starting write thread queue")
        self.write_thread = threading.Thread(
            target=self._write_thread_function, args=())
        self.write_thread.setDaemon(True)
        self.write_thread.start()

        store_data = ""
        command_list = []

        while self.main_loop is True:
            try:
                data = os.read(self.master, 1)

                if(self.echo_enabled is True):
                    os.write(self.master, data)

                print "{!r}".format(data)
                data = data.lower()

                if(store_data == "" and data == "a"):
                    store_data = data

                elif(store_data == "a"):
                    if(data == "t"):
                        store_data += data
                    else:
                        # Clear stored data for invalid char
                        store_data = ""

                elif(store_data == "at"):
                    if(data == "+"):
                        store_data += data
                    elif(data == "i"):
                        store_data += data
                    elif(data == "n"):
                        store_data += data
                    elif(data == "s"):
                        store_data += data
                    elif(data == "r"):
                        store_data += data
                    elif(data == "z"):
                        store_data += data
                    # elif(data == "b"):
                    #     store_data += data
                    elif(data == "\r"):
                        response = self.etrx3x_at.ok_response()
                        os.write(self.master, response)
                        store_data = ""
                    else:
                        # Clear stored data for invalid char
                        store_data = ""

                elif(len(store_data) >= 3):
                    if(data == "\r"):
                        if(store_data == "ati"):
                            response = self.etrx3x_at.ati_response(
                                self.local_node.get_node_eui())
                            response += self.etrx3x_at.ok_response()

                        elif(store_data == "ats"):
                            # return error message
                            # 05 = invalid_parameter
                            response = self.etrx3x_at.error_response("05")

                        elif(store_data == "atz"):
                            # TODO(rubens): check if it was connected to local
                            # pan to notify "JPAN" message
                            response = self.etrx3x_at.ok_response()

                        elif(store_data == "at+n"):
                            response = response = self.etrx3x_at.at_n_response(
                                self.local_node.get_type(),
                                self.local_pan.get_channel(),
                                self.local_pan.get_power(),
                                self.local_pan.get_pan_id(),
                                self.local_pan.get_epan_id()
                            )
                            response += self.etrx3x_at.ok_response()

                        elif(store_data == "at+tokdump"):
                            local_node_sregs = {}
                            for regs in self.local_node.get_sregisters():
                                local_node_sregs[regs[0]] = regs[1]

                            response = self.etrx3x_at.at_tokdump_response(
                                local_node_sregs)
                            response += self.etrx3x_at.ok_response()

                            store_data = ""

                        elif(re.match("at\+atable", store_data)):
                            # Get local pre-configured address table
                            local_atable = []
                            for addr in self.local_node.get_address_table():
                                if(addr[0] is True):
                                    active = "Y"
                                else:
                                    active = "N"

                                addr_entry = {
                                    "active": active,
                                    "node_id": addr[1],
                                    "node_eui": addr[2]
                                }
                                local_atable.append(addr_entry)

                            response = self.etrx3x_at.at_atable_response(
                                local_atable)

                        elif(re.match("ats[0-9a-f]{4}?", store_data)):
                            # atsXXPP = get local XX sregister with P bit
                            # position value for 32 bits sregisters
                            reg = store_data[3:5].upper()
                            bit_pos = store_data[5:7].upper()
                            try:
                                reg_prop = \
                                    self.etrx3x_at.\
                                    sregister_list_properties[reg]

                                if("bit_position" in reg_prop["rules"] and
                                        reg_prop["rules"]["bit_position"] is
                                        True):
                                    # return bit position value
                                    reg_value = self.local_node.\
                                        get_sregister_value(reg)
                                    bit_pos_int = int(bit_pos, 16)

                                    if(reg_value is not None):

                                        if(reg_prop["type"] == "hex16"):
                                            if(bit_pos_int > 15):
                                                # 05 = invalid_parameter
                                                response = self.etrx3x_at.\
                                                    error_response("05")

                                            else:
                                                # Get bit position from Little
                                                # Endian
                                                value = bin(int(
                                                    reg_value, 16))[2:][
                                                        (bit_pos_int * -1) - 1]

                                                response = self.etrx3x_at.\
                                                    ats_response(
                                                        reg + bit_pos, value)
                                                response += self.etrx3x_at.\
                                                    ok_response()
                                        else:
                                            # 05 = invalid_parameter
                                            response = self.etrx3x_at.\
                                                error_response("05")

                                    else:
                                        # Get bit position from Little Endian
                                        value = bin(int(
                                            reg_value, 16))[2:][
                                                (bit_pos_int * -1) - 1]

                                        response = self.etrx3x_at.ats_response(
                                            reg + bit_pos, value)
                                        response += \
                                            self.etrx3x_at.ok_response()

                                else:
                                    # return the sregister full content
                                    response = self.etrx3x_at.ats_response(
                                        reg, value)
                                    response += self.etrx3x_at.ok_response()

                            except KeyError as err:
                                print "keyerror: {} - {}".format(reg, err)
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                        elif(re.match("ats[0-9a-f]{3}?", store_data)):
                            # atsXXP = get local XX sregister with P bit
                            # position value
                            reg = store_data[3:5].upper()
                            bit_pos = store_data[5].upper()

                            try:
                                reg_prop = self.etrx3x_at.\
                                    sregister_list_properties[reg]

                                if(reg_prop["rules"] is not None and
                                        "bit_position" in reg_prop["rules"] and
                                        reg_prop["rules"]["bit_position"] is
                                        True):
                                    # return bit position value
                                    reg_value = self.local_node.\
                                        get_sregister_value(reg)

                                    if(reg_value is not None):
                                        bit_pos_int = int(bit_pos, 16)

                                        # Get bit position from Little Endian
                                        value = bin(int(
                                            reg_value, 16))[2:][(
                                                bit_pos_int * -1) - 1]

                                        response = self.etrx3x_at.ats_response(
                                            reg + bit_pos, value)
                                        response += self.etrx3x_at.\
                                            ok_response()
                                    else:
                                        # 05 = invalid_parameter
                                        response = self.etrx3x_at.\
                                            error_response("05")

                                else:
                                    # return the sregister full content
                                    response = self.etrx3x_at.ats_response(
                                        reg, value)
                                    response += self.etrx3x_at.ok_response()

                            except KeyError as err:
                                print "keyerror: {} - {}".format(reg, err)
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                        elif(re.match("ats[0-9a-f]{2}\?", store_data)):
                            # atsXX = get local s register
                            reg = store_data[3:5].upper()
                            value = self.local_node.get_sregister_value(reg)

                            if(value is not None):
                                response = self.etrx3x_at.ats_response(
                                    reg, value)
                                response += self.etrx3x_at.ok_response()

                            else:
                                print("local sregisters {} not found".format(
                                    reg))
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                        elif(re.match("ats[0-9a-f]{2}=[0-9a-z]*", store_data)):
                            # atsXX=V* = set local s register
                            reg = store_data[3:5].upper()
                            new_value = store_data[6:]
                            try:
                                etrx3x_at.validate_sregister_value(reg, value)

                                set_status = self.local_ndoe.set_sregisters(
                                    reg, value)

                                if(set_status is not None):
                                    response = self.etrx3x_at.ok_response()
                                else:
                                    response = self.etrx3x_at.error_response(
                                        "05")

                            except ValueError:
                                print(
                                    "invalid SRegister value {} for register "
                                    "{}".format(value, reg))
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                            except KeyError:
                                print("keyerror: {}".format(reg))
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                        elif(re.match("ats[0-9a-f]", data)):
                            # 05 = invalid_parameter
                            response = self.etrx3x_at.error_response("05")

                        # REMOTE COMMANDS - SHOULD INCLUDE SEQ-ACK
                        elif(re.match(
                                "at\+ntable:[0-9a-f]{2},[0-9a-f]{16}",
                                store_data)):
                            # NTABLE from address in node eui format (16 hexa)
                            params = store_data.split(":")[1].split(",")
                            try:
                                index = int(params[0], 16)

                            except ValueError:
                                index = -1

                            node = params[1]
                            if(validate_node_identifier(node) is False):
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                            else:
                                # TODO(rubens) use ZBNetwork data to find node
                                node_found = False
                                if(node_found is True):
                                    # "FF" - local node
                                    seq_num = self.get_seq_number()
                                    response = self.etrx3x_at.seq_response(
                                        seq_num)
                                    response += self.etrx3x_at.ok_response()

                                    error_code = "00"

                                    async_response = self.etrx3x_at.\
                                        at_ntable_response(
                                            self.local_node_id, error_code,
                                            index, self.local_node_ntable)
                                    async_response += self.etrx3x_at.\
                                        ack_response(seq_num)

                                    self.write_async_message(
                                        async_response,
                                        delay=0.1)
                                else:
                                    # Remote
                                    seq_num = self.get_seq_number()
                                    response = self.etrx3x_at.seq_response(
                                        seq_num)
                                    response += \
                                        self.etrx3x_at.ok_response()

                                    delay = int(
                                        self.local_node_sregs["4F"],
                                        16) / 1000

                                    async_response = self.etrx3x_at.\
                                        nack_response(seq_num)

                                    self.write_async_message(
                                        async_response, delay=delay)

                        elif(re.match(
                                "at\+ntable:[0-9a-f]{2},[0-9a-f]{4}",
                                store_data)):
                            # NTABLE from address in node id format (4 hexa)
                            params = store_data.split(":")[1].split(",")
                            try:
                                index = int(params[0], 16)

                            except ValueError:
                                index = -1

                            node = params[1]
                            if(validate_node_identifier(node) is False):
                                # 05 = invalid_parameter
                                response = self.etrx3x_at.error_response("05")

                            else:
                                # TODO(rubens) use ZBNetwork data to find node
                                node_found = False
                                if(node_found is True):
                                    # "FF" - local node
                                    seq_num = self.get_seq_number()
                                    response = self.etrx3x_at.seq_response(
                                        seq_num)
                                    response += self.etrx3x_at.ok_response()

                                    error_code = "00"

                                    async_response = self.etrx3x_at.\
                                        at_ntable_response(
                                            self.local_node_id, error_code,
                                            index, self.local_node_ntable)
                                    async_response += self.etrx3x_at.\
                                        ack_response(seq_num)

                                    self.write_async_message(
                                        async_response,
                                        delay=0.1)
                                else:
                                    # Remote
                                    seq_num = self.get_seq_number()
                                    response = self.etrx3x_at.seq_response(
                                        seq_num)
                                    response += \
                                        self.etrx3x_at.ok_response()

                                    delay = int(
                                        self.local_node_sregs["4F"],
                                        16) / 1000

                                    async_response = self.etrx3x_at.\
                                        nack_response(seq_num)

                                    self.write_async_message(
                                        async_response, delay=delay)

                        elif(re.match(
                                "at\+ntable:[0-9a-f]{2},[0-9a-f]{2}",
                                store_data)):
                            # NTABLE from address in ATABLE index format,
                            # or FF/ff to local node
                            params = store_data.split(":")[1].split(",")
                            try:
                                index = int(params[0], 16)

                            except ValueError:
                                index = -1

                            try:
                                address_table_index = int(params[1], 16)

                                if(address_table_index == 255):
                                    # "FF" - local node
                                    seq_num = self.get_seq_number()
                                    response = self.etrx3x_at.seq_response(
                                        seq_num)
                                    response += self.etrx3x_at.ok_response()

                                    error_code = "00"

                                    async_response = self.etrx3x_at.\
                                        at_ntable_response(
                                            self.local_node_id, error_code,
                                            index, self.local_node_ntable)
                                    async_response += self.etrx3x_at.\
                                        ack_response(seq_num)

                                    self.write_async_message(
                                        async_response,
                                        delay=0.1)
                                else:
                                    # Remote
                                    addr = self.local_node_atable[
                                        address_table_index]

                                    if(addr["node_id"] == "FFFF"):
                                        response = self.etrx3x_at.\
                                            error_response("01")
                                    else:
                                        seq_num = self.get_seq_number()
                                        response = self.etrx3x_at.seq_response(
                                            seq_num)
                                        response += \
                                            self.etrx3x_at.ok_response()

                                        delay = int(
                                            self.local_node_sregs["4F"],
                                            16) / 1000

                                        async_response = self.etrx3x_at.\
                                            nack_response(seq_num)

                                        self.write_async_message(
                                            async_response, delay=delay)

                            except ValueError:
                                # 05 - Invalid parameter
                                response = self.etrx3x_at.error_response("05")

                            except IndexError:
                                # 01 - could poll parent (default error for
                                # invalid address trable index)
                                response = self.etrx3x_at.error_response("01")

                        elif(re.match(
                                "at\+ucast:[0-9a-f]{2},[0-9a-f]{16}",
                                store_data)):
                            # NTABLE from address in node eui format (16 hexa)
                            # 05 = invalid_parameter
                            response = self.etrx3x_at.error_response("05")

                        elif(re.match(
                                "at\+ucast:[0-9a-f]{2},[0-9a-f]{4}",
                                store_data)):
                            # NTABLE from address in node id format (4 hexa)
                            # 05 = invalid_parameter
                            response = self.etrx3x_at.error_response("05")

                        elif(re.match(
                                "at\+ucast:[0-9a-f]{2},[0-9a-f]{2}",
                                store_data)):
                            # NTABLE from address in address index (16 hexa)
                            # 05 = invalid_parameter
                            response = self.etrx3x_at.error_response("05")

                        else:
                            # 02 = Invalid comand
                            response = self.etrx3x_at.error_response("02")

                        # Send response to serial port
                        self.write_serial(response)

                        # Clear stored data command
                        store_data = ""

                    else:
                        store_data += data

                else:
                    # Clear stored data for invalid char
                    store_data = ""

            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        self.main_loop = False


def main():
    default_router_etrx3x_sregs = {
        "00": "8000",  # channel 26
        "01": "-07",
        "02": "0000",
        "03": "0000000000000000",
        "04": "0000000000000000",
        "05": "0000",
        "06": "0000000000000000",
        "07": "0000",
        "08": "00000000000000000000000000000000",
        "09": "00000000000000000000000000000000",
        "0A": "8114",
        "0B": "Telegesis",
        "0C": "<hidden>",
        "0D": "ETRX357-Fake R309C",
        "0E": "0704",
        "0F": "01F8",
        "10": "0008",
        "11": "0005",
        "12": "0C10",
        "13": "00000000",
        "14": "00000000",
        "15": "00000600",
        "16": "000143CC",
        "17": "000142CC",
        "18": "00000100",
        "19": "00000000",
        "1A": "00DEBD33",
        "1B": "3A98",
        "1C": "3A98",
        "1D": "1D4C",
        "1E": "1D4C",
        "1F": "FFDC",
        "20": "FFDD",
        "21": "FFDE",
        "22": "FFDF",
        "23": "0001",
        "24": "0000",
        "25": "0000",
        "26": "0000",
        "27": "0000",
        "28": "0000",
        "29": "0004",
        "2A": "8010",
        "2B": "0000",
        "2C": "0000",
        "2D": "00F0",
        "2E": "8014",
        "2F": "0028",
        "30": "8015",
        "31": "0004",
        "32": "8300",
        "33": "000F",
        "34": "8400",
        "35": "04B0",
        "36": "801E",
        "37": "0000",
        "38": "0000",
        "39": "0000",
        "3A": "0000",
        "3B": "BUTTON3",
        "3C": "0000000000000;SGFake;1.0;0",
        "3D": "3072",
        "3E": "0000",
        "3F": "0000",
        "40": "0101",
        "41": "0101",
        "42": "0002",
        "43": "0002",
        "44": "C091",
        "45": "C091",
        "46": "00000000",
        "47": "C110",
        "48": "C091",
        "49": "0000",
        "4A": "0000",
        "4B": "",
        "4C": "",
        "4D": "0014",
        "4E": "0605",
        "4F": "1770"
    }

    default_coo_etrx3x_sregs = {
        "00": "8000",  # channel 26
        "01": "-07",
        "02": "0000",
        "03": "0000000000000000",
        "04": "0000000000000000",
        "05": "0000",
        "06": "0000000000000000",
        "07": "0000",
        "08": "00000000000000000000000000000000",
        "09": "00000000000000000000000000000000",
        "0A": "0114",
        "0B": "Telegesis",
        "0C": "<hidden>",
        "0D": "ETRX357-Fake R309C",
        "0E": "0704",
        "0F": "01F8",
        "10": "2218",
        "11": "0005",
        "12": "0C10",
        "13": "00000000",
        "14": "00000000",
        "15": "00000600",
        "16": "000143CC",
        "17": "000142CC",
        "18": "00000100",
        "19": "00000000",
        "1A": "00DEBD33",
        "1B": "3A98",
        "1C": "3A98",
        "1D": "1D4C",
        "1E": "1D4C",
        "1F": "FFDC",
        "20": "FFDD",
        "21": "FFDE",
        "22": "FFDF",
        "23": "0001",
        "24": "0000",
        "25": "0000",
        "26": "0000",
        "27": "0000",
        "28": "0000",
        "29": "0004",
        "2A": "8010",
        "2B": "003C",
        "2C": "821E",
        "2D": "00F0",
        "2E": "8013",
        "2F": "0028",
        "30": "8015",
        "31": "0004",
        "32": "8300",
        "33": "000F",
        "34": "8400",
        "35": "0000",
        "36": "0000",
        "37": "0000",
        "38": "0000",
        "39": "0000",
        "3A": "0000",
        "3B": "BUTTON3",
        "3C": "0000000000000;SGFake;1.0;0",
        "3D": "3072",
        "3E": "0000",
        "3F": "0000",
        "40": "0101",
        "41": "0101",
        "42": "0002",
        "43": "0002",
        "44": "C091",
        "45": "C091",
        "46": "00000000",
        "47": "C110",
        "48": "C091",
        "49": "0000",
        "4A": "0000",
        "4B": "",
        "4C": "",
        "4D": "0014",
        "4E": "0605",
        "4F": "1770"
    }

    etrx3x_configs = {
        "coo": default_coo_etrx3x_sregs,
        "router": default_router_etrx3x_sregs
    }

    coo_zbnode = {
        "id": "0000",
        "eui": "E000100000000000",
        "type": "COO",
        "parent_id": "FFFF",
        "sregs": {
            "3C": "5600010000000;SGFake;1.0;0"
        }
    }

    zbnode0 = {
        "id": "0001",
        "eui": "E000100000000001",
        "type": "FFD",
        "parent_id": "0000",
        "sregs": {
            "3C": "5600010000001;SGFake;1.0;0"
        }
    }

    zblink = {
        "id_src": "0000",
        "id_dst": "0001",
        "lqi": 255
    }

    pan = {
        "channel": 26,
        "id": "0001",
        "eid": "E000000000000001",
        "netkey": "00000000000000000000000000000001",
        "linkkey": "00000000000000000000000000000001"
    }

    zbnet0 = {
        "nodes": [coo_zbnode, zbnode0],
        "links": [zblink],
        "pan": pan,
    }

    etrx3x_sim = ETRX3xSimulator(
        [zbnet0],
        coo_zbnode["eui"],
        pan["eid"],
        router_etrx3x_sregs=default_router_etrx3x_sregs,
        coo_etrx3x_sregs=default_coo_etrx3x_sregs
    )

    print("Starting ETRX3x Simulator")

    etrx3x_sim.start()

    print("Terminating ETRX3x Network simulator")


if __name__ == '__main__':
    main()
