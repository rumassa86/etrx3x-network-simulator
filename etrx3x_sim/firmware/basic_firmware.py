#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Basic firmware library
#
from etrx3x_sim.zigbee import ZigBeeNetwork, ZigBeeNode
import threading
from etrx3x_sim.etrx3x_at_cmds import ETRX3xATCommand
import time


class ZBNetworkMCU(ZigBeeNetwork):
    def add_node(
        self,
            node_eui, node_type=None, node_id=None, name=None, version=None,
            enddevice=None, registers=None, node_state=None,
            serial_number=None, dev_type=None, dev_version=None, timeout=None,
            write_message=None):
        """Add node in network.

        Args:
            node: ZigBeeNode object.
        """
        # TODO(rubens): make this method to instantiate ZigBeeNode
        # object instead of main program.
        self.add_lock.acquire()
        node = self.get_node_eui(node_eui)
        if (node is None):
            # Create node and configure it
            if(dev_type == "echo"):
                node = ZBNodeEchoMCU(node_eui, write_message)
            else:
                node = ZigBeeNode(node_eui)

            node.set_node_id(node_id)
            node.set_type(node_type)
            node.set_name(name)
            node.set_version(version)
            node.set_enddevice(enddevice)
            node.set_state(node_state)
            node.set_timeout(timeout)
            if(registers is None):
                node.set_sregisters([])
            else:
                node.set_sregisters(registers)

            # SG device info
            node.set_serial_number(serial_number)
            node.set_device_type(dev_type)
            node.set_device_version(dev_version)

            self.node_list.append(node)
            self.add_lock.release()
        else:
            self.add_lock.release()
            # Update node on list
            self.update_node(node)

        return node


class ZBNodeBaseMCU(ZigBeeNode):
    def __init__(self, node_eui, write_message):
        super().__init__(node_eui)

        self.write_message = write_message

        self.mcu_alive = False
        self.mcu_thread = threading.Thread(
            target=self.mcu_main)
        self.mcu_thread.setDaemon(True)

        self.etrx3x_at = ETRX3xATCommand()

    def start(self):
        self.mcu_alive = True
        self.mcu_thread.start()

    def stop(self):
        self.mcu_alive = False
        self.mcu_thread.join()

    def mcu_main(self):
        pass

    def on_message(self, mac, message):
        pass


class ZBNodeEchoMCU(ZBNodeBaseMCU):
    def mcu_main(self):
        while(self.mcu_alive is True):
            time.sleep(1)

    def on_message(self, eui, message):
        response = self.etrx3x_at.ucast_notification(self.eui, message)

        print("{} -> {}: {}".format(eui, self.eui, message))
        if(self.write_message is not None):
            self.write_message(response.encode(), delay=0.3)
