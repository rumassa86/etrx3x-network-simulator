#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import hashlib
from time import time

# TODO(rubens): create exception class for each ZigBee class
# TODO(rubens): validate input data (parameters) of each method


class ZigBeePan:
    """Class of ZigBee PAN.

    This object contains data of ETRX3x ZigBee PAN data content.
    """
    def __init__(self, channel, power, pan_id, epan_id, zb_stack, joinable):
        """Constructor for ZigBeePan object.

        Args:
            channel: ZigBee PAN channel (range from 11 to 26).
            power: ZigBee radio signal power data.
            pan_id: ZigBee PAN identifier with 4 hexadecimal characters.
            epan_id: ZigBee Extend PAN identifier with 16 hexadecimal
                characters.
            zb_stack: ZigBee Stack version (00 = Custom, 01 = ZigBee,
                02 = ZigBee PRO).
            joinable: ZigBee joinable state (True is joinable, False is not
                joinable).
        """
        self.channel = channel
        self.power = power
        self.pan_id = pan_id
        self.epan_id = epan_id
        self.zb_stack = zb_stack
        self.joinable = joinable
        self.last_update = time()
        self.network_key = None
        self.link_key = None

    def __str__(self):
        """Print object in string format.
        """
        text = "PAN Info\n"
        text += "Channel    : " + str(self.channel) + "\n"
        text += "Power      : " + str(self.power) + "\n"
        text += "Pan ID     : " + str(self.pan_id) + "\n"
        text += "Extend PID : " + str(self.epan_id) + "\n"
        text += "zb_stack    : " + str(self.zb_stack) + "\n"
        text += "Joinable   : " + str(self.joinable) + "\n"
        text += "Last Update: " + str(self.last_update) + "\n"

        return text

    def get_channel(self):
        """Get ZigBee PAN channel.

        Returns:
            ZigBee PAN used channel.
        """
        return self.channel

    def get_power(self):
        """Get ZigBee PAN radio signal power.

        Returns:
            ZigBee PAN used radio signal power.
        """
        return self.power

    def get_pan_id(self):
        """Get ZigBee PAN identifier.

        Returns:
            ZigBee PAN identifier.
        """
        return self.pan_id

    def get_epan_id(self):
        """Get ZigBee PAN extended identifier.

        Returns:
            ZigBee PAN extended identifier.
        """
        return self.epan_id

    def get_zb_stack(self):
        """Get ZigBee PAN Stack version.

        Returns:
            ZigBee PAN Stack version wich values can be:
                00: Custom
                01: ZigBee
                02: ZigBee PRO
        """
        return self.zb_stack

    def get_joinable(self):
        """Get ZigBee PAN joinable state.

        Returns:
            True for joinable network, otherwise False for not joinable
            network.
        """
        return self.joinable

    def set_network_key(self, key):
        """Set ZigBee PAN Network key.

        Network key is used to encrypy the message in the ZigBee Network.

        Args:
            key: 32 hexadecimal characters.
        """
        self.key = key

    def get_network_key(self):
        """Get ZigBee PAN Network key.

        Network key is used to encrypy the message in the ZigBee Network.

        Returns:
            key: 32 hexadecimal characters.
        """
        return self.key

    def set_link_key(self, key):
        """Set ZigBee PAN Link key.

        Link key is used to obtain the Network key in ZigBee authentication
        process.

        Args:
            key: 32 hexadecimal characters.
        """
        self.key = key

    def get_link_key(self):
        """Get ZigBee PAN Link Key.

        Link key is used to obtain the Network key in ZigBee authentication
        process.

        Returns:
            key: 32 hexadecimal characters.
        """
        return self.key


class ZigBeeLink:
    """Class of ZigBee nodes link.

    This object contains data of a link between two network nodes.
    """
    def __init__(self, node_id_src, node_id_dest, lqi):
        """Constructor for ZigBee link object.

        Args:
            node_id_src: ZigBee source node identifier.
            node_id_dest: ZigBee destiny node identifier.
            lqi: Link signal quality.
        """
        self.node_id_src = node_id_src
        self.node_id_dest = node_id_dest
        self.quality = lqi
        self.last_contact = time()
        self.state = 1

    def __str__(self):
        """Print object in string format.
        """
        text = "Link {} -> {}\n".format(self.node_id_src, self.node_id_dest)
        text += "Quality: {}\n".format(self.quality)
        text += "Last Contact: {}\n".format(self.last_contact)
        return text

    def get_node_id_src(self):
        """Get source node identifier.

        Returns:
            ZigBee Node identifier with 4 hexadecimal characters.
        """
        return self.node_id_src

    def get_node_id_dest(self):
        """Get destiny node identifier.

        Returns:
            ZigBee Node identifier with 4 hexadecimal characters.
        """
        return self.node_id_dest

    def set_quality(self, quality):
        """Set link quality value.

        Args:
            quality: link quality in hexadecimal value (range from 00 to FF).
        """
        self.quality = quality

    def get_quality(self):
        """Get link quality value.

        Link value in hexadecimal ranging from 00 to FF.
        """
        return self.quality

    def perc_quality(self):
        """Get link quality value in float percentage.

        Returns:
            Link value in percentage value converted from hexadecimal.
            The value range from 00.0 (00) to 100.0 (FF).
        """
        try:
            dec = int(self.quality, 16)
        except TypeError:
            # FIXME: check correctly for empty string quality
            dec = int(self.quality)

        perc = round((float(dec) / 255) * 100)
        return perc

    def update_last_contact(self):
        """Set last contact (update) of link.
        """
        self.last_contact = time()

    def get_last_contact(self):
        """Get last contact (update) of link.

        Returns:
            Link last update timestamp.
        """
        return self.last_contact

    def set_state(self, state):
        """Set link state.

        Args:
            state: link state in decimal value. Values can be:
                0 = inactive
                1 = active
                2 = unknow
        """
        self.state = state

    def get_state(self):
        """Set link state.

        Returns:
            Link state decimal value:
                0 = inactive
                1 = active
                2 = unknow
        """
        return self.state

    def parse_state(self, state):
        """Parse link state.

        Args:
            state: link state in decimal value.

        Returns:
            Link state decimal value string:
                0 = "inactive"
                1 = "active"
                2 = "unknow"
        """
        if(state == 0):
            text = "inactive"
        elif(state == 1):
            text = "active"
        else:  # elif(state == 2):
            text = "unknow"
        return text


class ZigBeeRoute:
    """Class of specific ZigBee route.

    Route comes in ZigBee network stack header when an message is sent in the
    network. It starts with source node (where message is created) and reaches
    local node.
    """
    def __init__(self, eui, node_id, hash_index, route):
        """Constructor for ZigBeeRoute class.

        Args:
            eui: ZigBee node EUI.
            node_id: ZigBee node identififer.
            hash_index: node hash index based on route list.
            route: array of node identifiers with route.
        """
        self.eui = eui
        self.node_id = node_id

        # route contains the destination node_id
        self.route = route

        self.hash_index = hash_index

        # The destiny's node_id is not counted as a node route
        self.hops = len(route) - 1

        self.last_update = time()

    def __str__(self):
        text = "EUI: {}\n".format(self.eui)
        text += "NodeId: {}\n".format(self.node_id)
        text += "hash_index: {}\n".format(self.hash_index)
        text += "hops: {}\n".format(self.hops)
        text += "last_update: {}\n".format(self.last_update)
        text += "route: {}\n".format(self.route)

        return text

    def get_eui(self):
        """Get route node EUI in 16 char in hexadecimal string.

        Returns:
            Node EUI with 16 char in hexadecimal string.
        """
        return self.eui

    def get_node_id(self):
        """
        Get route node id in 4 char in hexadecimal string.

        Returns:
            Node identifier with 4 hexadecimal characters.
        """
        return self.node_id

    def set_node_id(self, node_id):
        """Set route node id in 4 char in hexadecimal string.

        Args:
            node_id: ZigBee node identifier.
        """
        # TODO test node_id parameters
        self.node_id = node_id

    def get_route(self):
        """Get route list which contains node id.

        Returns:
            List of route
        """
        return self.route

    def get_hash_index(self):
        """Get hash index of route.

        Hash index is defined on control class, such ZigBeeRouteControl.

        Returns:
            Return current route hash index.
        """
        return self.hash_index

    def get_hops(self):
        """Get the number of hops in route list.

        Returns:
            Amount of hops in current route.
        """
        return self.hops

    def get_last_update(self):
        """Get last update time for this route.

        Returns:
            Timestamp of last update in current route.
        """
        return self.last_update

    def set_last_update(self):
        """Set last update time for this route.

        Returns:
            Set last update timestamp.
        """
        self.last_update = time()


class ZigBeeRouteControl:
    """Class to manage routes of ZigBee network.

    All routes are based on local node perspective. The local node is the
    destiny of any route.
    """
    def __init__(self, max_route=100000):
        """Constructor for ZigBeeRouteControl

        Args:
            max_route: maximum amount of routes to be stored.
        """
        self.routes = []

        self.max_hops = None
        self.min_hops = None

        self.max_route = max_route

        self.add_lock = threading.Lock()

    def add_route(self, eui, node_id, route_list):
        """Add route with a hash index.

        Current implementation use the MD5 hash.

        Args:
            eui: ZigBee node EUI.
            node_id: ZigBee node identifier.
            route: route in list of ZigBee nodes. ex: ["ABFC", "0DFE",
                "EDD1"].
        """
        self.add_lock.acquire()
        route = self.get_route(route_list)
        if(route is None):
            # Test if maximum amount of route has been reached
            if(len(self.routes) < self.max_route):
                # Make has index base on route
                hash_index = self.make_index(route_list)

                route = ZigBeeRoute(eui, node_id, hash_index, route_list)

                self.routes.append(route)
                self.add_lock.release()

                # Set max_hops
                if(self.max_hops is None):
                    self.max_hops = route.get_hops()
                else:
                    if(self.max_hops < route.get_hops()):
                        self.max_hops = route.get_hops()

                # Set min_hops
                if(self.min_hops is None):
                    self.min_hops = route.get_hops()
                else:
                    if(self.min_hops > route.get_hops()):
                        self.min_hops = route.get_hops()
            else:
                self.add_lock.release()
                print("ERROR: maximum amount of routes reached.")
        else:
            # Update route
            route.set_last_update()
            self.add_lock.release()

    def get_route(self, route):
        """Get route based on route hash.

        This method is used only for unit test.

        Args:
            route: ZigBeeRoute object.

        Returns:
            Return the has List None if route was not found.
        """
        hash_index = self.make_index(route)
        for route in self.routes:
            if(route.get_hash_index() == hash_index):
                return route
        return None

    def has_route(self, route):
        """Test if route exist in routes.

        This method is used only for unit test.

        Returns:
            True if exists or False otherwise.
        """
        hash_index = self.make_index(route)
        for route in self.routes:
            if(route.get_hash_index() == hash_index):
                return True
        return False

    def get_max_hops(self):
        """Return the amount of hops from longest route.

        Returns:
            Amount of hops from longest route.
        """
        return self.max_hops

    def get_min_hops(self):
        """Return the amount of hops from shortest route.

        Returns:
            Amount of hops from shortest route.
        """
        return self.min_hops

    def get_total_routes(self):
        """Return to total amount of routes.

        Returns:
            Total amount of routes.
        """
        return len(self.routes)

    def get_routes_by_eui(self, eui):
        """Get all routes by source node EUI.

        Returns:
            List of ZigBeeRoute objects with origin in node EUI.
        """
        result_list = []
        for route in self.routes:
            if(route.get_eui() == eui):
                result_list.append(route)

        return result_list

    def get_routes_by_node_id(self, node_id):
        """Get all routes by node id source.

        Returns:
            List of ZigBeeRoute objects by source node id.
        """
        result_list = []
        for route in self.routes:
            if(route.get_node_id() == node_id):
                result_list.append(route)

        return result_list

    def get_routes_by_hops(self, hops):
        """Get all routes by amount of hops.

        Returns:
            List of ZigBeeRoute objects by amount of hops in route.
        """
        result_list = []
        for route in self.routes:
            if(route.get_hops() == hops):
                result_list.append(route)

        return result_list

    def get_all_routes(self):
        """Get all routes.

        Returns:
            List of all ZigBeeRout objects stored.
        """
        return self.routes

    def make_index(self, route):
        """Create index based on hash function over route.

        Current implementation concatenate all node id string and make a hash
        using the MD5 hash function.

        Args:
            route: list with nodes id. Ex: ["ABFC", "0DFE", "EDD1"].

        Returns:
            Hash using MD5 function over concatenated route list.
        """
        # Uses hash MD5 over concatenated route
        str_index = "".join(route)
        hash_function = hashlib.md5()
        hash_function.update(str_index)
        hash_index = hash_function.hexdigest()

        return hash_index


class ZigBeeNode:
    """Class of ZigBeeNode.
    """
    def __init__(self, eui):
        """Constructor for ZigBeeNode class.

        Args:
            eui: ZigBee node EUI.
        """
        # Node self data
        self.name = None  # Name
        self.node_id = None  # Identifier
        self.eui = eui  # MAC
        self.type = "FFD"
        self.parend_id = None
        self.parent_eui = None
        self.enddevice = "0000"

        # Timeout is used to define if this node is not
        # online, not responding or it has unknow state
        self.timeout = 600  # seconds - default 5minutes
        self.hops = 0  # number of hops to reach this node

        # Network data
        self.ntable = []  # item = [index, dev, EUI, node_id, LQI]
        self.rtable = []  # item = [dest, next_node, status, index]
        self.atable = []  # item = [active, node_id, node_eui]

        # Set max amount of routes to 100000
        # TODO: the max_route depends of number of nodes in the network
        self.routes = ZigBeeRouteControl(max_route=100000)

        # Configuration
        self.sregisters = []
        self.last_contact = time()
        self.version = None
        self.state = 4  # STATE UNKNOW

        # Supported endpoint list
        self.endpoints = []

        # ETRX3x specific node data
        self.sink_mode = False

        # Smartgreen Network node Data
        # TODO(rubens): create a SGZigBeeNode class to insert these
        # specifics data
        self.serial_number = None

        self.device_type = None

        self.device_version = "0.0"

    def __str__(self):
        text = "ZigBee Node [id={}]\n".format(self.node_id)
        text += "EUI: {}\n".format(self.eui)
        text += "NodeId: {}\n".format(self.node_id)
        text += "Name: {}\n".format(self.name)
        text += "Node type: {}\n".format(self.type)
        text += "Last Contact: {}\n".format(self.last_contact)
        text += "Version: {}\n".format(self.version)
        text += "Node State: {}\n".format(self.state)
        text += "Timout message (sec): {}\n".format(self.timeout)
        text += "Hops: {}\n".format(self.hops)
        text += "SRegisters:\n"
        text += str(self.sregisters) + "\n"
        text += "Neighbour Table:\n"
        text += "["

        first = True
        for i in self.ntable:
            if(first is False):
                text += ", "
            else:
                first = False

            text += "[{!r}, {!r}, {!r}, {}, {}]".format(
                i.get_node_id_src(), i.get_node_id_dest(), i.get_quality(),
                i.get_last_contact(), i.get_state())

        text += "]\n"
        text += "Routing Table:\n"
        text += str(self.rtable) + "\n"

        return text

    def set_node_id(self, node_id):
        """Set node identifier.

        Args:
            node_id: ZigBee node identifier.
        """
        self.node_id = node_id

    def get_node_id(self):
        """Get node identifier.

        Returns:
            ZigBee node identifier.
        """
        return self.node_id

    def set_type(self, new_type):
        """Set node type.

        Args:
            new_type: new node type.
        """
        self.type = new_type

    def get_type(self):
        """Get node type.

        Returns:
            Node type in string format:
                "FFD" = full function device
                "SED" = sleep enddevice
                "ZED" = zigbee enddevice (non-sleep)
                "MED" = mobile enddevice
        """
        return self.type

    def get_node_eui(self):
        """Get node eui.

        Returns:
            Zigbee node EUI.
        """
        return self.eui

    def add_address_entry(self, active, node_id, node_eui):
        """Add ETRX3x Address Table entry.

        This method is used only in ETRX3x ZiBee module.

        Args:
            active: address entry status. True for active, False for inactive.
            node_id: ZigBee Node identififer.
            node_eui: ZigBee Node EUI identifier
        """
        self.atable.append([active, node_id, node_eui])

    def set_address_entry(self, index, active, node_id, node_eui):
        """set ETRX3x Address Table entry.

        This method is used only in ETRX3x ZiBee module.

        Args:
            index: address table index.
            active: address entry status. True for active, False for inactive.
            node_id: ZigBee Node identififer.
            node_eui: ZigBee Node EUI identifier

        Returns:
            Entry if set with success or None if failed to found entry.
        """
        entry = self.get_address_entry(index)

        if(entry is not None):
            entry[0] = active
            entry[1] = node_id
            entry[2] = node_eui

        return entry

    def get_address_table(self):
        """Get Address table.

        This method is used only in ETRX3x ZiBee module.

        Returns:
            List of address table entries.
        """
        return self.atable

    def get_address_entry(self, index):
        """Get Address table entry by table index.

        This method is used only in ETRX3x ZiBee module.

        Args:
            index: address table index in integer value.

        Returns:
            Entry found or None if entry index is out of range.
        """
        try:
            entry = self.atable[index]
        except IndexError:
            return None

    def add_sregister(self, register, value):
        """Add ETRX3x SRegister configuration value.

        This method is used only in ETRX3x ZiBee module.

        Args:
            register: SRegister number (in 2 hexadecimal character).
            value: SRegister value.
        """
        register_up = register.upper()

        reg = self.get_sregister(register_up)
        if(reg is None):
            # Add new register
            reg = [register_up, value]
            self.sregisters.append(reg)
        else:
            # Update value
            reg[1] = value

    def get_sregister(self, register):
        """Get ETRX3x SRegister with register identifier and value.

        This method is used only in ETRX3x ZiBee module.

        Args:
            register: SRegister number (in 2 hexadecimal character).

        Returns:
            Tuple with SRegister number and value content.
        """
        reg = None
        register_up = register.upper()
        for i in self.sregisters:
            if(i[0] == register_up):
                reg = i
                break
        return reg

    def get_sregister_value(self, register):
        """Get only ETRX3x SRegister value.

        This method is used only in ETRX3x ZiBee module.

        Args:
            register: SRegister number (in 2 hexadecimal character).

        Returns:
            SRegister value content.
        """
        value = None
        reg = self.get_sregister(register)

        if(reg is not None):
            value = reg[1]

        return value

    def set_sregister_value(self, register, value):
        """Set only ETRX3x SRegister value.

        This method is used only in ETRX3x ZiBee module.

        Args:
            register: SRegister number (in 2 hexadecimal character).
            value: register value in string format.

        Returns:
            Set operation status: True for success and False for fail.
        """
        return_status = False
        reg = self.get_sregister(register)

        if(reg is not None):
            reg[1] = value
            return_status = True

        return return_status

    def get_sregisters(self):
        """Get all SRegisters values stored.

        This method is used only in ETRX3x ZiBee module.


        Returns:
            List with all tuples of SRegister number and value.
        """
        return self.sregisters

    def set_sregisters(self, sregister_array):
        """Set all SRegisters values stored.

        This method is used only in ETRX3x ZiBee module.

        Args:
            sregister_array: list with SRegister tuple with register number
                and value.
        """
        self.sregisters = sregister_array

    def set_name(self, name):
        """Set node name.

        This name is stored in some modules to identify the product type
        (application data).

        Args:
            name: ZigBee device name in application context.
        """
        self.name = name

    def get_name(self):
        """Set node name.

        This name is stored in some modules to identify the product type
        (application data).

        Returns:
            ZigBee device name in application context.
        """
        return self.name

    def update_last_contact(self):
        """Update last contact timestamp.

        The timestamp is updated using current system timestamp.
        """
        self.last_contact = time()

    def set_last_contact(self, timestamp):
        """Set last contact timestamp.

        Args:
            timestamp: time in epoch timestamp UTC format.
        """
        self.timestamp = timestamp

    def get_last_contact(self):
        """Get last contact timestamp.

        Returns:
            Timestamp of last node contact.
        """
        return self.last_contact

    def set_version(self, version):
        """Set ZigBee module version.

        Args:
            version: ZigBee module version in string format.
        """
        self.version = version

    def get_version(self):
        """Get ZigBee module version.

        Returns:
            ZigBee module version in string format.
        """
        return self.version

    def set_state(self, state):
        """Set ZigBee node state in decimal number.

        Args:
            state: node state number. Node state can be:
                0 = "offline"
                1 = "online"
                2 = "unknow"
                3 = "fail or not responding"
                4 = "sleepy"
                5 = "Inactive (minor time)"
                6 = "Inactive (major time)"
        """
        self.state = state

    def get_state(self):
        """Get ZigBee node state in decimal number.

        Return:
            Node state number. Node state can be:
                0 = "offline"
                1 = "online"
                2 = "unknow"
                3 = "fail or not responding"
                4 = "sleepy"
                5 = "Inactive (minor time)"
                6 = "Inactive (major time)"
        """
        return self.state

    def is_sink(self):
        """Get SINK mode of current node instance.

        Returns:
            True if it is SINK or False otherwise.
        """
        return self.sink_mode

    def enable_sink(self):
        """Enable sink mode on current node.
        """
        self.sink_mode = True

    def disable_sink(self):
        """Disable sink mode on current node.
        """
        self.sink_mode = False

    def parse_state(self, state):
        """Set ZigBee node state in decimal number.

        Args:
            state: node state number. Node state can be:
                0 = "offline"
                1 = "online"
                2 = "unknow"
                3 = "fail or not responding"
                4 = "sleepy"
                5 = "Inactive (minor time)"
                6 = "Inactive (major time)"
        """
        if(state == 0):
            text = "offline"
        elif(state == 1):
            text = "online"
        elif(state == 2):
            text = "unknow"
        elif(state == 3):
            text = "fail or not responding"
        elif(state == 4):
            text = "sleepy"
        elif(state == 5):
            text = "Inactive (minor time)"
        else:
            # elif(state == 6):
            text = "Inactive (major time)"
        return text

    def set_parent_id(self, node_id):
        """Set ZigBee parent node id.

        Args:
            node_id: parent ZigBee node identifier.
        """
        self.parend_id = node_id

    def get_parent_id(self):
        """Get ZigBee parent node id.

        Returns:
            Parent ZigBee node identifier.
        """
        return self.parend_id

    def set_parent_eui(self, eui):
        """Set ZigBee parent node EUI.

        Args:
            eui: parent ZigBee node EUI.
        """
        self.parent_eui = eui

    def get_parent_eui(self):
        """Get ZigBee parent node EUI.

        Returns:
            Parent ZigBee node EUI.
        """
        return self.parent_eui

    def set_enddevice(self, enddevice):
        """Set ZigBee endpoint device id.

        This method is used in ETRX3x to store device type for endpoint 2.

        Args:
            enddevice: endpoint device id with 4 hexadecimal chars.
        """
        self.enddevice = enddevice

    def get_enddevice(self):
        """Get ZigBee endpoint device id.

        This method is used in ETRX3x to store device type for endpoint 2.

        Returns:
            Endpoint device id with 4 hexadecimal chars.
        """
        return self.enddevice

    def set_timeout(self, timeout):
        """Set ZigBee node timeout.

        Args:
            timeout: timestamp timeout used as reference to set node state.
        """
        self.timeout = timeout

    def get_timeout(self):
        """Get ZigBee node timeout.

        Returns:
            Timestamp timeout used as reference to set node state.
        """
        return self.timeout

    def set_hops(self, hops):
        """Set amount of hops to reach current node.

        Args:
            hops: amount of hops in decimal value.
        """
        self.hops = hops

    def get_hops(self):
        """Get amount of hops to reach current node.

        Returns:
            Amount of hops in decimal value.
        """
        return self.hops

    def set_serial_number(self, value):
        """Set enddevice serial number.

        This is an application data store in ZigBee module.

        Args:
            value: serial number in string format.
        """
        self.serial_number = value

    def get_serial_number(self):
        """Get enddevice serial number.

        This is an application data store in ZigBee module.

        Returns:
            Serial number in string format.
        """
        return self.serial_number

    def set_device_type(self, value):
        """Set enddevice type.

        This is an application data store in ZigBee module.

        Args:
            value: enddevice type value in string format.
        """
        self.device_type = value

    def get_device_type(self):
        """Get enddevice type.

        This is an application data store in ZigBee module.

        Returns:
            Enddevice type value in string format.
        """
        return self.device_type

    def set_device_version(self, value):
        """Set enddevice version.

        This is an application data store in ZigBee module.

        Args:
            value: enddevice version value in string format.
        """
        self.device_version = value

    def get_device_version(self):
        """Get enddevice version.

        This is an application data store in ZigBee module.

        Returns:
            Enddevice version value in string format.
        """
        return self.device_version

    def add_neighbour(self, node_id_src, node_id_dest, lqi=0):
        """Add neighbour link to current node.

        Add neighbour by adding ZigBeeLink.

        Args:
            link: ZigBeeLink object with neighbour data.
        """
        # Check if exists link to neighbour
        link = self.get_neighbour(node_id_dest)
        if(link is None):
            # Add neighbour link
            link = ZigBeeLink(node_id_src, node_id_dest, lqi)
            self.ntable.append(link)
        else:
            # Update neighbour link quality
            link.set_quality(lqi)
        return link

    def get_ntable(self):
        """Get all neighbour links of current node.

        Returns:
            List of ZigBeeLink with all neighbour stored in current node.
        """
        return self.ntable

    def get_neighbour(self, node_id):
        """Get neighbour link by node id.

        Args:
            node_id: neighbour ZigBee node identifer.

        Returns:
            ZigBeeLink object with neighbour node identifier.
        """
        link = None
        for i in self.ntable:
            if (i.get_node_id_dest() == node_id):
                link = i
                break
        return link

    def remove_neighbour(self, node_id):
        """Remove neighbour link by node identifier.

        Args:
            node_id: neighbour ZigBee node identifer.

        Returns:
            ZigBeeLink object if removed with success or None if
            link was not found.
        """
        link = self.get_neighbour(node_id)

        if(link is not None):
            self.ntable.remove(link)

        return link

    def update_link(self, node_id, lqi=None):
        """Update neighbour link by ZigBee node identifier.

        Args:
            node_id: neighbour ZigBee node identifer.

        Returns:
            ZigBeeLink object if removed with success or None if
            link was not found.
        """
        link = self.get_neighbour(node_id)
        if (link is not None):
            link.update_last_contact()
            link.set_state(1)  # Link active

            if(lqi is not None):
                link.set_quality(lqi)

        return link

    def clear_ntable(self):
        """Clear neighbour list.

        Remove all neighbour from current node.
        """
        # Remove all nodes from neighbour list
        for i in range(len(self.ntable) - 1, -1, -1):
            node = self.ntable[i]
            self.ntable.remove(node)

    def get_rtable(self):
        """Get all local node routing table.

        Returns:
            List of routing instance. Routing instance has the format:
                [dest, next_node, status, index]

                dest: ZigBee node id destiny.
                next_node: ZigBee node id to next.
                status: routing status defined in ZigBee specification.
                index: routing entry index in routing table.
        """
        # TODO(rubens): create ZigBeeRoute class
        return self.rtable

    def add_routing(self, index, dest, next_node, status):
        """Add routing entry to current node.

        Args:
            index: routing entry index in routing table.
            dest: ZigBee node id destiny.
            next_node: ZigBee node id to next.
            status: routing status defined in ZigBee specification.
        """
        # TODO(rubens): create ZigBeeRoute class
        node = [dest, next_node, status, index]
        self.rtable.append(node)

    def get_routing(self, node_id):
        """Get routing entry by Zigbee node identifier.

        Args:
            node_id: ZigBee node identifier.

        Returns:
            None if was not found or routing instance in format:
                [dest, next_node, status, index]

                dest: ZigBee node id destiny.
                next_node: ZigBee node id to next.
                status: routing status defined in ZigBee specification.
                index: routing entry index in routing table.
        """
        # TODO(rubens): create ZigBeeRoute class
        node = None
        for i in self.rtable:
            if(i[0] == node_id):
                node = i
                break
        return node

    def remove_routing(self, node_id):
        """Remove routing entry by ZigBee node identifer.

        Args:
            node_id: ZigBee node identifier.

        Returns:
            True if removed with success or False if entry was not found.
        """
        # TODO(rubens): create ZigBeeRoute class
        node = self.get_neighbour(node_id)
        if(node is not None):
            self.rtable.remove(node)
            return True
        else:
            return False


class ZigBeeNetwork:
    """ZigBee network control class.
    """
    def __init__(self):
        """Constructor for ZigBeeNetwork class.
        """
        self.local_node = None
        self.local_pan = None
        self.sink = None
        self.node_list = []  # item = ZigBeeNode()
        self.pan_list = []  # item = ZigBeePan()

        self.password = None
        self.key = None

        self.add_lock = threading.Lock()

    def __str__(self):
        text = "ZigBee Network Object\n"
        text += "Local Node: \n"
        text += "  " + str(self.local_node).replace("\n", "\n  ") + "\n"

        text += "Local PAN:\n"
        text += "  " + str(self.local_pan).replace("\n", "\n  ") + "\n"
        text += "Sink:\n"
        text += "  " + str(self.sink).replace("\n", "\n  ") + "\n"

        text += "Node List:\n"
        for i in self.node_list:
            text += " - " + str(i.node_id) + ", " + str(i.type) + "\n"

        text += "PAN list:\n"

        for i in range(0, len(self.pan_list)):
            pan = self.pan_list[i]
            text += " " + str(i) + " - " + str(pan.channel)
            text += ", " + str(pan.pan_id) + "\n"

        return text

    def set_sink(self, sink_node):
        """Set network sink node.

        This is a ETRX3x feature.

        Args:
            sink_node: ZigBeeNode object.
        """
        self.sink = sink_node

    def get_sink(self):
        """Get network sink node.

        This is a ETRX3x feature.

        Returns:
            Sink ZigBeeNode object.
        """
        return self.sink

    def get_node_list(self):
        """Get all stored nodes in network.

        Returns:
            List with ZigBeeNode objects.
        """
        return self.node_list

    def get_pan_list(self):
        """Get all stored ZigBee PAN detected.

        Returns:
            List with all ZigBeePan objects.
        """
        return self.pan_list

    def add_node(
        self,
            node_eui, node_type=None, node_id=None, name=None, version=None,
            enddevice=None, registers=None, node_state=None,
            serial_number=None, dev_type=None, dev_version=None, timeout=None):
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

    def update_node(
        self,
            node_eui, node_id=None, name=None, version=None,
            enddevice=None, registers=[], node_state=None,
            serial_number=None, dev_type=None, dev_version=None,
            timeout=None):
        """Add node in network.

        Args:
            node: ZigBeeNode object.
        """
        node = self.get_node_eui(node_eui)
        if (node is not None):
            # Update node values
            if(node_id is not None):
                node.set_node_id(node_id)

            if(name is not None):
                node.set_name(name)

            if(version is not None):
                node.set_version(version)

            if(enddevice is not None):
                node.set_enddevice(enddevice)

            if(registers is not []):
                node.set_sregisters(registers)

            if(node_state is not None):
                node.set_state(node_state)

            if(timeout is not None):
                node.set_timeout(timeout)

            # SG device info
            if(serial_number is not None):
                node.set_serial_number(serial_number)

            if(dev_type is not None):
                node.set_device_type(dev_type)

            if(dev_version is not None):
                node.set_device_version(dev_version)

    def remove_node(self, node_id, use_node_id=True):
        """Remove node from current network.

        Args:
            node_id: ZigBee node identifier.
            use_node_id: flag to use node identifier or node eui to find
                node in node list. Values can be:
                    True = use 4 hexa node id.
                    False = use 16 hexa node eui.
        """
        if (use_node_id is True):
            node = self.get_node(node_id)
        else:
            node = self.get_node_eui(node_id)

        if(node is not None):
            # Remove all links from neighbours
            for link in node.ntable:
                neighbour_id = link.get_node_id_dest()
                if(neighbour_id is not None):
                    neighbour = self.get_node(neighbour_id)
                    # Some cases, the node_id has neighbour
                    # that is not present in node_list
                    # FIX: Check this case and find the
                    # reasons to add a node that is not
                    # present in this network.
                    if (neighbour is not None):
                        neighbour.remove_neighbour(node_id)

            # Remove node from nodelist
            self.node_list.remove(node)

    def get_node(self, node_id):
        """Get node by node identifier.

        Args:
            node_id: ZigBee node identifier.
        """
        node = None
        for i in self.node_list:
            if(int(i.node_id, 16) == int(node_id, 16)):
                node = i
                break
        return node

    def get_node_eui(self, eui):
        """Get node by node eui.

        Args:
            eui: ZigBee node EUI.
        """
        node = None
        for i in self.node_list:
            if(int(i.eui, 16) == int(eui, 16)):
                node = i
                break
        return node

    def clear_node_list(self):
        """Remove all nodes from node_list.
        """
        for i in range(len(self.node_list) - 1, -1, -1):
            node = self.node_list[i]
            self.node_list.remove(node)

        # Clear local node
        self.set_local_node(None)

    def get_local_node(self):
        """Get local node instance.

        Returns:
            ZigBeeNode instance of local node.
        """
        return self.local_node

    def set_local_node(self, node):
        """Set local node.

        Args:
            node: ZigBeeNode object of local node.
        """
        self.local_node = node

    def set_local_pan(self, pan):
        """Set local PAN.

        Args:
            pan: ZigBeePan object of local node.
        """
        self.local_pan = pan

    def get_local_pan(self):
        """Get local PAN.

        Returns:
            ZigBeePan object of local node.
        """
        return self.local_pan

    def get_pan(self, pan_id):
        """Get PAN by PAN identifier.

        Args:
            pan_id: ZigBee PAN identifier or EPAN identifier.

        Returns:
            None if not found or ZigBeePan object.
        """
        pan = None
        for i in self.pan_list:
            if(len(pan_id) == 4):
                if(i.get_pan_id() == pan_id):
                    pan = i
                    break
            if(len(pan_id) == 16):
                if(i.get_epan_id() == pan_id):
                    pan = i
                    break
        return pan

    def get_pan_index(self, index):
        """Get PAN by PAN index.

        Args:
            index: index of PAN in local pan list.

        Returns:
            None if not found or ZigBeePan object.
        """
        if (len(self.pan_list) > 0):
            return self.pan_list[index]
        else:
            return None

    def add_pan(self, channel, power, pan_id, epan_id, zb_stack, joinable):
        """Add new pan to local structure.

        Args:
            channel: ZigBee PAN channel (range from 11 to 26).
            power: ZigBee radio signal power data.
            pan_id: ZigBee PAN identifier with 4 hexadecimal characters.
            epan_id: ZigBee Extend PAN identifier with 16 hexadecimal
                characters.
            zb_stack: ZigBee Stack version (00 = Custom, 01 = ZigBee,
                02 = ZigBee PRO).
            joinable: ZigBee joinable state (True is joinable, False is not
                joinable).

        Returns:
            ZigBeePan object added to structure.

        """
        pan = self.get_pan(pan_id)

        if(pan is None):
            pan = ZigBeePan(
                channel, power, pan_id, epan_id, zb_stack, joinable)
            self.pan_list.append(pan)

        return pan

    def remove_pan(self, pan_id):
        """Remove PAN by PAN identifier.

        Args:
            pan_id: ZigBee PAN identifier (4 hexadecimal chars).
        """
        pan = self.get_pan(pan_id)
        if(pan is not None):
            self.get_pan(pan)

    def clear_pan_list(self):
        """Remove all PANs in the pan list.
        """
        for i in range(len(self.pan_list) - 1, -1, -1):
            node = self.pan_list[i]
            self.pan_list.remove(node)

        # Clear local pan
        self.set_local_pan(None)

    def set_password(self, password):
        """Set current network local node module password.

        This is used in ETRX3x module.

        Args:
            password: string with 8 characters.
        """
        self.password = password

    def get_password(self):
        """Get current network local node module password.

        This is used in ETRX3x module.

        Returns:
            String with 8 characters.
        """
        return self.password

    def set_key(self, key):
        """Set current network key (link and network keys).

        Args:
            key: string with 32 hexadecimal characters with 128 bit key.
        """
        self.key = key

    def get_key(self):
        """Get current network key (link and network keys).

        Returns:
            String with 32 hexadecimal characters with 128 bit key.
        """
        return self.key

    def add_link(self, node_id_src, node_id_dest, lqi=0):
        """Add link to ZigBee network structure.

        Args:
            node_id_src: source ZigBee node identifier.
            node_id_dest: destiny ZigBee node identifier.
            lqi: link signal quality (default=0).

        Returns:
            ZigBeeLink object or None if node was not found or source
            and destiny node identifier has the same value.
        """
        if(node_id_src == node_id_dest):
            return None

        node = self.get_node(node_id_src)
        if(node is not None):
            link = node.add_neighbour(
                node_id_src, node_id_dest, lqi=lqi)

        else:
            # Node not found
            link = None

        return link

    def remove_link(self, node_id_src, node_id_dest):
        """Add link to ZigBee network structure.

        Args:
            node_id_src: source ZigBee node identifier.
            node_id_dest: destiny ZigBee node identifier.
            lqi: link signal quality (default=0).

        Returns:
            ZigBeeLink object or None if node was not found or source
            and destiny node identifier has the same value.
        """
        if(node_id_src == node_id_dest):
            return None

        link = None
        node = self.get_node(node_id_src)
        if(node is not None):
            link = node.remove_neighbour(node_id_dest)

        return link

    def get_link(self, node_id_src, node_id_dest):
        """Get neighbour link.

        Args:
            node_id_src: source ZigBee node identifier.
            node_id_dest: destiny ZigBee node identifier.

        Returns:
            ZigBeeLink object or None if node was not found or source
            and destiny node identifier has the same value.
        """
        if(node_id_src == node_id_dest):
            return None

        link = None
        node = self.get_node(node_id_src)
        if(node is not None):
            link = node.get_neighbour(node_id_dest)

        return link

    def update_link(self, node_id_src, node_id_dest, lqi=0):
        """Update link data in ZigBee network structure.

        Args:
            node_id_src: source ZigBee node identifier.
            node_id_dest: destiny ZigBee node identifier.
            lqi: link signal quality (default=0).

        Returns:
            ZigBeeLink object or None if node was not found or source
            and destiny node identifier has the same value.
        """
        if(node_id_src == node_id_dest):
            return None

        link = None
        node = self.get_node(node_id_src)
        if(node is not None):
            link = node.update_link(
                node_id_dest, lqi=lqi)

        return link

    def clear_node_links(self):
        """Remove all links from all nodes.
        """
        for node in self.node_list:
            node.clear_ntable()
