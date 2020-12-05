#!/usr/bin/env python
# -*- coding: utf-8 -*-

# See ETRX2 and ETRX3 Series ZigBee Modules AT-Command Dictionary
#
# IMPLEMENTATION OF AT COMMANDS USED BY TELEGESIS ETRX3x
# This program just create and parser AT commands
#
# Supported Firmware:
# ETRX357-LRS - R308C

# NOTE
# AT commands network messages use 3 identifiers:
#  EUI: an MAC address in EUI64 format
#  NodeID: an 4 hexadecimals represents the node ID
#  TableEntry: id on neighbour or routing table
#  NOTE: for a more consistent syntax, use NodeID as first identifier,
#        then EUI and TableEntry. Use EUI when node is not connect to
#        any PAN.
#
#
# NOTE
# Serial interface requires a '\r' character at the end of command.
# This class dont put the '\r' in the message, handle it in main program
#

import re

from lib.sgcon_validators import validate_node_identifier
from lib.sgcon_validators import validate_zigbee_channel_range
from lib.sgcon_validators import check_node_id_format
from lib.sgcon_validators import check_node_eui_format


class ETRX3xATCommandException(Exception):
    """ETRX3xATCommandException exception error class
    """
    def __init__(self, msg):
        """Constructor for ETRX3xATCommandException class.

        Args:
            msg: message to describe the error.
        """
        super(ETRX3xATCommandException, self).__init__()
        self.msg = msg

    def __str__(self):
        return "{}".format(self.msg)


class ETRX3xATCommand:
    """Class to handle AT commands used to communicate with ETRX3x module.
    """
    sregister_list_properties = {
        "00": {"type": "hex16", "rules": {"bit_position": True}},  # ZBChannels
        "01": {"type": "int16", "rules": {"values": [
            8, 7, 6, 5, 4, 3, 2, 1, -1, -2, -3, -4, -5, -6, -7, -8, -9,
            -11, -12, -14, -17, -20, -26, -43]}},  # Power level for R309C
        "02": {"type": "hex16", "rules": {"bit_position": True}},
        "03": {"type": "hex64", "rules": None},
        "04": {"type": "hex64", "rules": None},
        "05": {"type": "hex16", "rules": {
            "max_value": 0xFFF7, "bit_position": True}},
        "06": {"type": "hex64", "rules": None},
        "07": {"type": "hex16", "rules": {
            "max_value": 0xFFF7, "bit_position": True}},
        "08": {"type": "hex128", "rules": None},  # Network Key
        "09": {"type": "hex128", "rules": None},  # TrustCentre Link Key
        "0A": {"type": "hex16", "rules": {"bit_position": True}},
        "0B": {"type": "str", "rules": {"max_len": 16}},  # module password
        "0C": {"type": "str", "rules": {"max_len": 8}},
        "0D": {"type": "str", "rules": {"max_len": 100}},
        "0E": {"type": "hex16", "rules": {"bit_position": True}},
        "0F": {"type": "hex16", "rules": {"bit_position": True}},
        "10": {"type": "hex16", "rules": {"bit_position": True}},
        "11": {"type": "hex16", "rules": {"bit_position": True}},
        "12": {"type": "hex16", "rules": {"bit_position": True}},
        "13": {"type": "hex32", "rules": {"bit_position": True}},
        "14": {"type": "hex16", "rules": {"bit_position": True}},
        "15": {"type": "hex32", "rules": {"bit_position": True}},
        "16": {"type": "hex32", "rules": {"bit_position": True}},
        "17": {"type": "hex32", "rules": {"bit_position": True}},
        "18": {"type": "hex32", "rules": {"bit_position": True}},
        "19": {"type": "hex32", "rules": {"bit_position": True}},
        "1A": {"type": "hex32", "rules": {"bit_position": True}},
        "1B": {"type": "hex16", "rules": {"bit_position": True}},
        "1C": {"type": "hex16", "rules": {"bit_position": True}},
        "1D": {"type": "hex16", "rules": {"bit_position": True}},
        "1E": {"type": "hex16", "rules": {"bit_position": True}},
        "1F": {"type": "hex16", "rules": {"bit_position": True}},
        "20": {"type": "hex16", "rules": {"bit_position": True}},
        "21": {"type": "hex16", "rules": {"bit_position": True}},
        "22": {"type": "hex16", "rules": {"bit_position": True}},
        "23": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "24": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "25": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "26": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "27": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "28": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "29": {"type": "hex16", "rules": {"bit_position": True}},
        "2A": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "2B": {"type": "hex16", "rules": {"bit_position": True}},
        "2C": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "2D": {"type": "hex16", "rules": {"bit_position": True}},
        "2E": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "2F": {"type": "hex16", "rules": {"bit_position": True}},
        "30": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "31": {"type": "hex16", "rules": {"bit_position": True}},
        "32": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "33": {"type": "hex16", "rules": {"bit_position": True}},
        "34": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "35": {"type": "hex16", "rules": {"bit_position": True}},
        "36": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "37": {"type": "hex16", "rules": {"bit_position": True}},
        "38": {"type": "hex16", "rules": {
            "builtin": True, "bit_position": True}},
        "39": {"type": "hex16", "rules": {
            "max_value": 0x0003, "bit_position": True}},
        "3A": {"type": "hex16", "rules": {
            "max_value": 0x0003, "bit_position": True}},
        "3B": {"type": "str", "rules": {"max_len": 50}},
        "3C": {"type": "str", "rules": {"max_len": 50}},
        "3D": {"type": "int16", "rules": {
            "min_value": 0, "max_value": 9999}},
        "3E": {"type": "hex16", "rules": {"bit_position": True}},
        "3F": {"type": "hex16", "rules": {"bit_position": True}},
        "40": {"type": "hex16", "rules": {"bit_position": True}},
        "41": {"type": "hex16", "rules": {"bit_position": True}},
        "42": {"type": "hex16", "rules": {"bit_position": True}},
        "43": {"type": "hex16", "rules": {"bit_position": True}},
        "44": {"type": "hex16", "rules": {"bit_position": True}},
        "45": {"type": "hex16", "rules": {"bit_position": True}},
        "46": {"type": "hex32", "rules": {"bit_position": True}},
        "47": {"type": "hex16", "rules": {"bit_position": True}},
        "48": {"type": "hex16", "rules": {"bit_position": True}},
        "49": {"type": "hex16", "rules": {"bit_position": True}},
        "4A": {"type": "hex16", "rules": {
            "max_value": 0x00FF, "bit_position": True}},
        "4B": {"type": "hex16_list", "rules": {"max_len": 12}},
        "4C": {"type": "hex16_list", "rules": {"max_len": 12}},
        "4D": {"type": "hex16", "rules": {
            "max_value": 0x00FF, "bit_position": True}},
        "4E": {"type": "hex16", "rules": {
            "max_value": 0x0EFF, "bit_position": True}},
        "4F": {"type": "hex16", "rules": {
            "max_value": 0x7530, "bit_position": True}}
    }

    def __init__(self):
        """ETRX3 AT constructor
        """

    def get_sregister_list_properties(self):
        return self.sregister_list_properties

    def validate_etrx3x_node_identifier(
        self, node_id,
            only_node_id=False, only_eui=False, only_index=False):
        """Validate ETRX3x node identifier.

        If 'only_node_id' is True, it will ignore 'only_eui' and 'only_index'
        values, even if those values are True.

        If 'only_node_id' is False and 'only_eui' it True, it will ignore
        'only_index' value, even if its value is True.

        Node identifier can be:
            * 2 hexadecimal characters (node index in local module address
                Table)
            * 4 hexadecimal characters (node id in ZigBee Network)
            * 16 hexadecimal characters (node EUI or mac address in 802.15.4)

        Args:
            password: ETRX3x password value content.
            only_node_id: flag to validate only node id (default=None).
            only_eui: flag to validate only node eui (default=None).
            only_index: flag to validate only node table index (default=None).

        Raises:
            TypeError: password data type diferente from string.
            ValueError: password content format is not alpha-numeric.
        """
        if(isinstance(node_id, str) is False):
            raise TypeError("invalid node_id type: {}".format(type(node_id)))

        if((only_node_id is False) and (only_eui is False) and
                (only_index is False)):
            # Check for address table format with 2 hexadecimal chars
            if(len(node_id) == 2):
                if(re.match("[0-9A-F]{2}", node_id.upper()) is None):
                    raise ValueError(
                        "invalid node_id value: {!r}".format(node_id))

            elif(validate_node_identifier(node_id) is False):
                raise ValueError(
                    "invalid node_id value {!r}".format(node_id))

        elif(only_node_id is True):
            if(check_node_id_format(node_id) is False):
                raise ValueError(
                    "invalid node_id value {!r}".format(node_id))

        elif((only_node_id is False) and (only_eui is True)):
            if(check_node_eui_format(node_id) is False):
                raise ValueError(
                    "invalid node_id value {!r}".format(node_id))

        else:  # only_index = True
            if(len(node_id) == 2):
                if(re.match("[0-9a-fA-F]{2}", node_id) is None):
                    raise ValueError(
                        "invalid node_id value: {!r}".format(node_id))
            else:
                raise ValueError(
                    "invalid node_id value: {!r}".format(node_id))

    def validate_etrx3x_password(self, password):
        """Validate ETRX3x password data.

        Args:
            password: ETRX3x password value content.

        Raises:
            TypeError: password data type diferente from string.
            ValueError: password content format is not alpha-numeric.
        """
        if(isinstance(password, str) is False):
            raise TypeError("invalid password type: {}".format(
                type(password)))

        if(re.match("[0-9a-zA-F]{8}", password) is None):
            raise ValueError("invalid password value: {!r}".format(password))

    def validate_sregister_number(self, sregister):
        """Validate sregister number based on the ETRX308 document.

        Args:
            sregister: number of target sregister ETRX308 list range.

        Raises:
            TypeError: invalid sregister data type. Must be string type.
            ValueError: sregister number is out of ETRX308 list range.
        """
        if(isinstance(sregister, str) is False):
            raise TypeError("invalid sregister type: {}".format(
                type(sregister)))

        sreg = sregister.upper()

        if(len(sreg) != 2):
            raise ValueError(
                "invalid sregister length: {!r}".format(len(sregister)))

        if(re.match("[0-9A-F]{2}", sreg) is None):
            raise ValueError(
                "invalid sregister value: {!r}".format(sregister))

        if(sreg in self.sregister_list_properties is False):
            raise ValueError(
                "invalid ETRX3x sregister: {!r}".format(sreg))

    def validate_sregister_value(self, sregister, value):
        """Validate SRegister number and respective value based on ETRX308
        document.

        Args:
            sregister: SRegister number with 2 hexadecimal chars.
            value: string value to be validade.

        Raises:
            TypeError: invalid sregister or value data type different from
                string.
            ValueError: invalid sregister or value content for SRegister.
        """
        # item format = (
        #   sregister_number,
        #   <type>,
        #   <restrict_rules>
        # )
        # <type> field has the follow definitions:
        #     hex16 = content has str 4 hex characters
        #     hex16_list = content contains an list of hex16
        #     hex32 = content has str 8 hex characters
        #     hex64 = content has str 16 hex characters
        #     hex128 = content has str 32 hex characters
        #     int16 = content has integer 16 bits value
        #     str = content has string chars
        # <restrict_rules> is a dict with specific rules to validade
        #     register value. Restrict rules has the follow fields:
        #     {
        #         "values": list of specifics values. It ignore others rules.
        #         "max_value": integer maximum value
        #         "min_value": integer minimum value
        #         "max_len": maximum length of str or list
        #         "min_len": minimum length of str or list
        #         "builtin": flag to validade as builtin function
        #     }

        sreg = sregister.upper()

        try:
            self.validate_sregister_number(sreg)

        except TypeError as err:
            raise err

        except ValueError as err:
            raise err

        if(isinstance(value, str) is False):
            raise TypeError(
                "validate_sregister_value: invalid value type: {}".format(
                    type(value)))

        sreg_type = self.sregister_list_properties[sreg]["type"]
        sreg_rules = self.sregister_list_properties[sreg]["rules"]

        if sreg_type in ["hex16", "hex32", "hex64", "hex128"]:
            try:
                int_value = int(value, 16)
            except ValueError:
                raise ValueError(
                    "validate_sregister_value: invalid hex value"
                    " {!r}".format(value))

            # Validate builtin function format
            if(sreg_rules is not None):
                if(("builtin" in sreg_rules) and
                        (sreg_rules["builtin"] is True)):
                    try:
                        self.validate_builtin_function(value)
                        return

                    except ValueError as err:
                        raise ValueError(
                            "validate_sregister_value: {!r}".format(err))

            # Test hexadecimal values
            min_value = 0x0000

            if(sreg_type == "hex16"):
                max_value = 0xFFFF

            elif(sreg_type == "hex32"):
                max_value = 0xFFFFFFFF

            elif(sreg_type == "hex64"):
                max_value = 0xFFFFFFFFFFFFFFFF

            else:  # hex128
                max_value = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

            if(sreg_rules is not None):
                if "min_value" in sreg_rules:
                    min_value = sreg_rules["min_value"]

                if "max_value" in sreg_rules:
                    max_value = sreg_rules["max_value"]

            if((int_value < min_value) and (int_value > max_value)):
                raise ValueError(
                    "validate_sregister_value: invalid sregister"
                    " {!r} value {!r}".format(sreg, value))

        elif(sreg_type == "int16"):
            try:
                int_value = int(value)
            except ValueError:
                raise ValueError(
                    "validate_sregister_value: invalid integer value"
                    " {!r}".format(value))

            min_value = 0
            max_value = 65535

            if(sreg_rules is not None):
                if "min_value" in sreg_rules:
                    min_value = sreg_rules["min_value"]

                if "max_value" in sreg_rules:
                    max_value = sreg_rules["max_value"]

            if((int(value) < min_value) and (int(value) > max_value)):
                raise ValueError(
                    "validate_sregister_value: invalid sregister"
                    " {!r} value {!r}".format(sreg, value))

        elif(sreg_type == "str"):
            min_len = 0
            max_len = 200

            if(sreg_rules is not None):
                if "min_len" in sreg_rules:
                    min_len = sreg_rules["min_len"]

                if "max_len" in sreg_rules:
                    max_len = sreg_rules["max_len"]

            if((len(value) < min_len) and (len(value) > max_len)):
                raise ValueError(
                    "validate_sregister_value: invalid sregister length"
                    " {!r} value {!r}".format(sreg, value))

        elif(sreg_type == "hex16_list"):
            min_len = 0
            max_len = 30

            if(sreg_rules is not None):
                if "min_len" in sreg_rules:
                    min_len = sreg_rules["min_len"]

                if "max_len" in sreg_rules:
                    max_len = sreg_rules["max_len"]

            if((len(value) < min_len) and (len(value) > max_len)):
                raise ValueError(
                    "validate_sregister_value: invalid sregister"
                    " {!r} value {!r}".format(sreg, value))

            try:
                if(value == ""):
                    id_list = []
                else:
                    id_list = value.split(",")
                self.validate_cluster_id_list(id_list)

            except TypeError as err:
                raise TypeError(
                    "validate_sregister_value: {}".format(err))

            except ValueError as err:
                raise ValueError(
                    "validate_sregister_value {}".format(err))

    def validate_builtin_function(self, value):
        """Validate builtin function value described in ETRX308 document.

        Args:
            value: builtin function value in 4 hexadecimal chars.

        Raises:
            TypeError: invalid builtin function data type.
            ValueError: invalid builtin function value.
        """
        builtin_list = [
            "0000",
            "0001",
            "0002",
            "0003",
            "0004",
            "0010",
            "0011",
            "0012",
            "0013",
            "0014",
            "0015",
            "0016",
            "0017",
            "0018",
            "001D",
            "001E",
            "001F",
            "0020",
            "0021",
            "0108",
            "0109",
            "0110",
            "0111",
            "0112",
            "0113",
            "0114",
            "0115",
            "0116",
            "0117",
            "0118",
            "0119",
            "0120",
            "0121",
            "0130",
            "0131",
            "0300",
            "0301",
            "0302",
            "0400",
            "0401",
            "2000",
            "2001",
            "2100",
            "2101",
            "003X",
            "004X",
            "005X",
            "006X",
            "02XX",
            "24XX",
            "25XX",
            "26XX",
            "3XXX",
            "4XXX"
        ]

        if(isinstance(value, str) is False):
            raise TypeError("invalid builtin value type: {}".format(
                type(value)))

        int_value = int(value, 16)

        # Ignore loop builtin flag bit
        if(int_value >= 0x8000):
            int_value = int_value - 0x8000

        max_builtin_int_value = 0
        min_builtin_int_value = 0

        for builtin_value in builtin_list:
            # Get range limits of builtin values
            try:
                max_builtin_int_value = int(builtin_value, 16)
                min_builtin_int_value = int(builtin_value, 16)

            except ValueError:
                if(builtin_value[1:] == "XXX"):

                    min_builtin_int_value = int(builtin_value[0] + "000", 16)
                    max_builtin_int_value = int(builtin_value[0] + "FFF", 16)

                elif(builtin_value[2:] == "XX"):
                    min_builtin_int_value = int(builtin_value[0:1] + "00", 16)
                    max_builtin_int_value = int(builtin_value[0:1] + "FF", 16)

                elif(builtin_value[3:] == "X"):
                    min_builtin_int_value = int(builtin_value[0:2] + "0", 16)
                    max_builtin_int_value = int(builtin_value[0:2] + "F", 16)

            # Test is equal or in range of valid builtin value
            if(((int_value > min_builtin_int_value) and
                    (int_value < max_builtin_int_value)) or
                    (int_value == max_builtin_int_value)):
                return

        raise ValueError("invalid builtin function value: {!r}".format(
            value))

    def validate_bit_position(self, bit_position):
        """Validate bit position of target SRegister content.

        Args:
            bit_positon: bit number of targer SRegister content. I can be
                one hexadecimal character for 16 bits content or two
                hexadecimal character for 32 bits content.

        Raises:
            TypeError: invalid bit position data type.
            ValueError: invalid bit position value.
        """
        if(isinstance(bit_position, str) is False):
            raise TypeError("invalid bit_position type: {}".format(
                bit_position))

        if(len(bit_position) > 2):
            raise ValueError(
                "bit_position grater than 2 chars {!r}".format(
                    len(bit_position)))

        if(re.match("[0-9A-Z]{1,2}", bit_position.upper()) is None):
            raise ValueError(
                "invalid bit_position hexadecimal value {!r}".format(
                    len(bit_position)))

    def validate_update_id(self, update_id):
        """Validate update id field used in AT+SJN.

        Args:
            bit_positon: bit number of targer SRegister content. I can be
                one hexadecimal character for 16 bits content or two
                hexadecimal character for 32 bits content.

        Raises:
            TypeError: invalid bit position data type.
            ValueError: invalid bit position value.
        """
        if(isinstance(update_id, str) is False):
            raise TypeError("invalid update_id type: {}".format(
                update_id))

        if(len(update_id) != 2):
            raise ValueError(
                "update_id grater different from 2 chars {!r}".format(
                    len(update_id)))

        if(re.match("[0-9A-Z]{2}", update_id.upper()) is None):
            raise ValueError(
                "invalid update_id hexadecimal value {!r}".format(
                    len(update_id)))

    def validate_group_id(self, group_id):
        """Validate group id used to send broadcasts for target ZigBee devices.

        Args:
            group_id: string with 4 hexadecimal chars that must be
                'FFFC', 'FFFD', 'FFFF'.

        Raises:
            TypeError: invalid bit position data type.
            ValueError: invalid bit position value.
        """
        valid_group_id_values = ["FFFC", "FFFD", "FFFF"]

        if(isinstance(group_id, str) is False):
            raise TypeError("invalid group_id type: {}".format(
                group_id))

        if group_id not in valid_group_id_values:
            raise ValueError(
                "invalid group_id value {!r}".format(
                    len(group_id)))

    def validate_zigbee_channel(self, channel):
        """Validate ZigBee Channel range value.

        Args:
            channel: ZigBee channel integer in range of 11 and 26.

        Raises:
            TypeError: invalid ZigBee channel data type.
            ValueError: invalid ZigBee channel value.
        """
        if(isinstance(channel, int) is False):
            raise TypeError("invalid channel type: {}".format(
                channel))

        if(validate_zigbee_channel_range(channel) is False):
            raise ValueError("invalid channel value {!r}".format(channel))

    def validate_zigbee_pan(self, pan_id):
        """Validate ZigBee PAN identifier value.

        Args:
            pan_id: ZigBee PAN identifier.

        Raises:
            TypeError: invalid ZigBee PAN identifier data type.
            ValueError: invalid ZigBee PAN identifier value.
        """
        if(isinstance(pan_id, str) is False):
            raise TypeError("invalid pan_id type: {}".format(
                pan_id))

        if(validate_node_identifier(pan_id) is False):
            raise ValueError("invalid pan_id value {!r}".format(pan_id))

    def validate_table_index(self, index):
        """Validate ETRX3x module internal table index value.

        Args:
            index: table index range from 0 to 255 (8 bits).

        Raises:
            TypeError: invalid ETRX3x table index data type.
            ValueError: invalid ETRX3x table index value.
        """
        if(isinstance(index, int) is False):
            raise TypeError("invalid index type: {}".format(index))

        if(index < 0 or index > 255):
            raise ValueError("invalid index value {!r}".format(index))

    def validate_endpoint_number(self, endpoint):
        """Validate ETRX3x endpoint number.

        Args:
            endpoint: endpoint number in string 2 hexadecimal chars.

        Raises:
            TypeError: invalid ZigBee endpoint number data type.
            ValueError: invalid ZigBee endpoint number value.
        """
        if(isinstance(endpoint, str) is False):
            raise TypeError("invalid endpoint number type: {}".format(
                endpoint))

        if(len(endpoint) != 2):
            raise ValueError(
                "endpoint number without 2 hexadecimal chars {!r}".format(
                    endpoint))

        if(re.match("[0-9A-F]{2}", endpoint.upper()) is None):
            raise ValueError(
                "invalid endpoint number value {!r}".format(
                    endpoint))

    def validate_profile_id(self, profile_id):
        """Validate profile id number.

        Args:
            profile_id: endpoint number in string 2 hexadecimal chars.

        Raises:
            TypeError: invalid ZigBee profile identifier data type.
            ValueError: invalid ZigBee profile identifier value.
        """
        try:
            self.validate_etrx3x_node_identifier(
                profile_id, only_node_id=True)

        except TypeError:
            raise TypeError("invalid profile_id number type: {}".format(
                profile_id))

        except ValueError:
            raise ValueError(
                "invalid profile_id number value {!r}".format(
                    profile_id))

    def validate_cluster_id(self, cluster_id):
        """Validate ZigBee cluster identifier number.

        Args:
            cluster_id: cluster identifier with 4 hexadecimal chars.

        Raises:
            TypeError: invalid ZigBee cluster identifier data type.
            ValueError: invalid ZigBee cluster identifier value.
        """
        try:
            self.validate_etrx3x_node_identifier(
                cluster_id, only_node_id=True)

        except TypeError:
            raise TypeError("invalid cluster_id type: {}".format(
                cluster_id))

        except ValueError:
            raise ValueError(
                "invalid cluster_id value {!r}".format(
                    cluster_id))

    def validate_cluster_id_list(self, cluster_id_list):
        """Validate list of ZigBee cluster identifier.

        Args:
            cluster_id_list: list of cluster_id.

        Raises:
            TypeError: invalid list of ZigBee cluster identifier data type.
            ValueError: invalid list ofZigBee cluster identifier value.
        """
        if(isinstance(cluster_id_list, list) is False):
            raise TypeError("invalid cluster_id_list type: {}".format(
                type(cluster_id_list)))

        for cluster_id in cluster_id_list:
            try:
                self.validate_cluster_id(cluster_id)

            except TypeError:
                raise TypeError("invalid cluster_id_list item type: {}".format(
                    type(cluster_id)))

            except ValueError:
                raise ValueError(
                    "invalid cluster_id item value {!r}".format(
                        cluster_id))

    def validate_node_list(self, node_list):
        """Validate list of ZigBee nodes id.

        Args:
            node_list: list of node id.

        Raises:
            TypeError: invalid list of ZigBee node id data type.
            ValueError: invalid list of ZigBee node id value.
        """
        if(isinstance(node_list, list) is False):
            raise TypeError("invalid node_list type: {}".format(
                type(node_list)))

        for node_id in node_list:
            try:
                self.validate_etrx3x_node_identifier(
                    node_id, only_node_id=True)

            except TypeError:
                raise TypeError("invalid node_list item type: {}".format(
                    type(node_id)))

            except ValueError:
                raise ValueError(
                    "invalid node_list item value {!r}".format(
                        node_id))

    def validate_hops(self, hops):
        """Validate ZigBee hops value.

        Args:
            hops: amount of hops in integer value from 0 to 30.

        Raises:
            TypeError: invalid ETRX3x table index data type.
            ValueError: invalid ETRX3x table index value.
        """
        if(isinstance(hops, int) is False):
            raise TypeError("invalid hops type: {}".format(hops))

        if(hops < 0 or hops > 30):
            raise ValueError("invalid hops value {!r}".format(hops))

    def validate_multicast_id(self, multicast_id):
        """Validate ZigBee multicast identifier number.

        Args:
            multicast_id: multicast identifier with 4 hexadecimal chars.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        try:
            self.validate_etrx3x_node_identifier(
                multicast_id, only_node_id=True)

        except TypeError:
            raise TypeError("invalid multicast_id type: {}".format(
                multicast_id))

        except ValueError:
            raise ValueError(
                "invalid multicast_id value {!r}".format(
                    multicast_id))

    def validate_message_payload(self, message):
        """Validate ETRX3x ZigBee UCAST message payload, follow the
        limitations described in ETRX308 document.

        Args:
            message: string payload message sent in ZigBee messages over
                the network. This messages contains the size of 0 to 82
                characters.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(message, str) is False):
            raise TypeError("invalid message payload type: {}".format(
                message))

        if((len(message) < 0 and len(message) > 82)):
            raise ValueError("invalid message payload value {!r}".format(
                message))

    def validate_message_length(self, message_length):
        """Validate ETRX3x ZigBee UCAST message payload length, follow
        the limitations described in ETRX308 document.

        Args:
            message_length: integer payload message length sent in ZigBee
                messages over the network, from 0 to 82

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(message_length, int) is False):
            raise TypeError("invalid message_length payload type: {}".format(
                message_length))

        if(message_length < 0 and message_length > 82):
            raise ValueError(
                "invalid message_length payload value {!r}".format(
                    message_length))

    def validate_track_message_id(self, message_id):
        """Validate track message identifier.

        Args:
            message_id: integer message identifier in 16 bits range.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(message_id, int) is False):
            raise TypeError("invalid message_id type: {}".format(
                message_id))

        if(message_id < 0 and message_id > 0xFFFF):
            raise ValueError(
                "invalid message_id value {!r}".format(
                    message_id))

    def validate_track_sequence_number(self, sequence_num):
        """Validate track message sequence number.

        Args:
            sequence_num: integer message sequence identifier in 16 bits
                range.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(sequence_num, int) is False):
            raise TypeError("invalid sequence_num type: {}".format(
                sequence_num))

        if(sequence_num < 0 and sequence_num > 0xFFFF):
            raise ValueError(
                "invalid sequence_num value {!r}".format(
                    sequence_num))

    def validate_track_level(self, track_level):
        """Validate track message sequence number.

        Args:
            track_level: integer message sequence identifier in 16 bits
                range.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(track_level, int) is False):
            raise TypeError("invalid track_level type: {}".format(
                track_level))

        if(track_level < 0 and track_level > 2):
            raise ValueError(
                "invalid track_level value {!r}".format(
                    track_level))

    def validate_bind_type(self, bind):
        """Validate ETRX3x binding type.

        Args:
            bind: binding type value.

        Raises:
            TypeError: invalid ZigBee multicast identifier data type.
            ValueError: invalid ZigBee multicast identifier value.
        """
        if(isinstance(bind, int) is False):
            raise TypeError("invalid bind type: {}".format(bind))

        if(bind < 0 and bind > 3):
            raise ValueError(
                "invalid bind value {!r}".format(bind))

    def validate_message_id(self, message_id):
        """Validate notification endpoint identifier

        Args:
            message_id: message_id interger value

        Raises:
            TypeError: invalid notify identifier data type.
            ValueError: invalid notify identifier value.
        """
        if(isinstance(message_id, int) is False):
            raise TypeError("invalid message_id type: {}".format(message_id))

        if(message_id < 0 and message_id > 65535):
            raise ValueError(
                "invalid message_id value {!r}".format(message_id))

    def local_info(self):
        """Get local module information command.

        Return the AT command used to retrieve product identification
        and information.

        Returns:
            String "ATI".
        """
        return "ATI"

    def local_reset(self):
        """Get local module soft reset command.

        Returns:
            String "ATZ".
        """
        return "ATZ"

    def local_restore(self):
        """Get local module restore default configurations command.

        Returns:
            String "AT&F".
        """
        return "AT&F"

    def local_bootloader(self):
        """Get local module to enter in bootloader menu command.

        Returns:
            String "AT+BLOAD".
        """
        return "AT+BLOAD"

    def local_clone(self, node_id, password):
        """Get command to clone local node to remote node.

        This command only works on ETRX2 Series.

        Args:
            node_id: ETRX3x ZigBee node identifier with 4 hexadecimal chars
                or EUI64 format.
            password: remote node password.

        Returns:
            String with "AT+CLONE:<node_id>,<password>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "local_clone: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "local_clone: {}".format(err))

        try:
            self.validate_etrx3x_password()

        except ValueError as err:
            raise ETRX3xATCommandException(
                "local_clone: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "local_clone: {}".format(err))

        return "AT+CLONE:{},{}".format(node_id, password)

    def local_pass_firmware(self, node_id, password):
        """Get command to pass new firmware image To Remote Node.

        This command only works on ETRX3 Series.

        Args:
            node_id: node address in EUI64 format.
            password: remote node password.

        Returns:
            String with "AT+PASSTHROUGH:<node_id>,<password>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "local_pass_firmware: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "local_pass_firmware: {}".format(err))

        try:
            self.validate_etrx3x_password(password)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "local_pass_firmware: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "local_pass_firmware: {}".format(err))

        if(password is not None):
            msg = "AT+PASSTHROUGH:{},{}".format(node_id, password)
        else:
            msg = "AT+PASSTHROUGH:{}".format(node_id)

        return msg

    def clone_recover(self):
        """Get command to recover from a failed clone attempt.

        Returns:
            String with "AT+RECOVER".
        """
        return "AT+RECOVER"

    def read_sregister(self, register_number, bit_position=None):
        """Get command to read local S-Register with bits selection.

        Command format is ATSXX[x[x]] where:
            XX is the S-Register which is to be read.

            As an option for all 16 bit registers it is also possible to
            address an individual bit only by specifying the bit number [x].

            For all 32 bit registers it is possible to address an
            individual bit by specifying the bit number in hexadecimal [xx]

        Args:
            register_number: register number identifier in hexadecimal.
            bit_position: bit flag position in hexadecimal char. If register
                is a 16bits range value, bit posisiton contains one char from
                '0' to 'F'. If it is 32bits bit possition contains two chars
                from '00' to 'FF'.

        Returns:
            String with "ATS<register_number><bit_position>?".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_sregister_number(register_number.upper())

        except ValueError as err:
            raise ETRX3xATCommandException(
                "read_sregister: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "read_sregister: {}".format(err))

        if(bit_position is not None):
            try:
                self.validate_bit_position(bit_position.upper())

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "read_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "read_sregister: {}".format(err))

            target_reg = "{}{}".format(register_number, bit_position)

        else:
            target_reg = "{}".format(register_number)

        return "ATS{}?".format(target_reg)

    def write_sregister(
        self, register_number, data, bit_position=None,
            password=None):
        """Get command to write local S-Register with bits selection.

        Command format is ATSXX[x[x]]=<data>,<password> where:
            XX is the S-Register which is to be read.

            As an option for all 16 bit registers it is also possible to
            address an individual bit only by specifying the bit number [x].

            For all 32 bit registers it is possible to address an
            individual bit by specifying the bit number in hexadecimal [xx]

        Args:
            register_number: string register number identifier with
                2 hexadecimal characters.
            bit_position: bit flag position in hexadecimal.
            data: register value.
            password: local module password (default=None).

        Returns:
            String with in format:
            "ATS<register_number><bit_position>=<data>[,<password>]".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_sregister_value(register_number, data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "write_sregister: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "write_sregister: {}".format(err))

        if(bit_position is not None):
            try:
                self.validate_bit_position(bit_position)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_sregister: {}".format(err))

            target_reg = "{}{}".format(register_number, bit_position)

        else:
            target_reg = "{}".format(register_number)

        # Some registers require local module password to write on it.
        # It can be sent even the sregister do not require the password.
        if(password is not None):
            try:
                self.validate_sregister_value(register_number, data)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_sregister: {}".format(err))

            msg = "ATS{}={},{}".format(
                target_reg, data, password)
        else:
            msg = "ATS{}={}".format(
                target_reg, data)

        return msg

    def read_remote_sregister(
        self, node_id, register_number,
            bit_position=None):
        """Get command to read remote S-Register with bits selection.

        Command format is ATREMSXX[x[x]]=<data>,<password> where:
            XX is the S-Register which is to be read.

            As an option for all 16 bit registers it is also possible to
            address an individual bit only by specifying the bit number [x].

            For all 32 bit registers it is possible to address an
            individual bit by specifying the bit number in hexadecimal [xx]

        Args:
            node_id: remote node address (node id or EUI64 format).
            register_number: register number identifier in hexadecimal.
            bit_position: bit flag position in hexadecimal.

        Returns:
            String with "ATREMS:<node_id>,<register_number><bit_position>?".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id)
            self.validate_sregister_number(register_number)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "read_remote_sregister: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "read_remote_sregister: {}".format(err))

        if(bit_position is not None):
            try:
                self.validate_bit_position(bit_position)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "read_remote_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "read_remote_sregister: {}".format(err))

            target_reg = "{}{}".format(register_number, bit_position)

        else:
            target_reg = "{}".format(register_number)

        return "ATREMS:{},{}?".format(
            node_id, target_reg)

    def write_remote_sregister(
        self, node_id, register_number, data, bit_position,
            password):
        """Get command to read remote S-Register with bits selection.

        Command format is ATREMSXX[x[x]]=<data>,<password> where:
            XX is the S-Register which is to be read.

            As an option for all 16 bit registers it is also possible to
            address an individual bit only by specifying the bit number [x].

            For all 32 bit registers it is possible to address an
            individual bit by specifying the bit number in hexadecimal [xx]

        Args:
            node_id: remote node address (node id or EUI64 format).
            register_number: register number identifier in hexadecimal.
            bit_position: bit flag position in hexadecimal.
            data: register value.
            password: remote module password.

        Returns:
            String in format:
            "ATREMS:<node_id>,<register_number><bit_position>=<data>,<password>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id)
            self.validate_sregister_value(register_number, data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "write_remote_sregister: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "write_remote_sregister: {}".format(err))

        if(bit_position is not None):
            try:
                self.validate_bit_position(bit_position)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_remote_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_remote_sregister: {}".format(err))

            target_reg = "{}{}".format(register_number, bit_position)

        else:
            target_reg = "{}".format(register_number)

        # Some registers require local module password to write on it.
        # It can be sent even the sregister do not require the password.
        if(password is not None):
            try:
                self.validate_sregister_value(register_number, data)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_remote_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_remote_sregister: {}".format(err))

            msg = "ATREMS:{},{}={},{}".format(
                node_id, target_reg, data, password)

        else:
            msg = "ATREMS:{},{}={}".format(
                node_id, target_reg, data)

        return msg

    def write_group_remote_sregister(
        self, group_id, register_number, data, bit_position=None,
            password=None):
        """Get command to write remote S-Register of group nodes
            with bits selection.

        Command format is "ATSALL:<group_id>,[x[x]]=<data>,<password>"
        where:
            XX is the S-Register which is to be read.

            As an option for all 16 bit registers it is also possible to
            address an individual bit only by specifying the bit number [x].

            For all 32 bit registers it is possible to address an
            individual bit by specifying the bit number in hexadecimal [xx]

        Args:
            group_id: node group by type as remote nodes multicast id:
                "FFFF" = Broadcast to all devices
                "FFFD" = Broadcast to all non-sleepy devices
                "FFFC" = Broadcast to all Routers
            register_number: register number identifier in hexadecimal.
            bit_position: bit flag position in hexadecimal.
            data: register value.
            password: remote module password.

        Returns:
            String in format:
            "ATSALL:<group_id>,<data>,<register_number><bit_position>=<data>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_group_id(group_id)
            self.validate_sregister_value(register_number, data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "write_group_remote_sregister: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "write_group_remote_sregister: {}".format(err))

        if(bit_position is not None):
            try:
                self.validate_bit_position(bit_position)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_group_remote_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_group_remote_sregister: {}".format(err))

            target_reg = "{}{}".format(register_number, bit_position)

        else:
            target_reg = "{}".format(register_number)

        # Some registers require local module password to write on it.
        # It can be sent even the sregister do not require the password.
        if(password is not None):
            try:
                self.validate_sregister_value(register_number, data)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "write_group_remote_sregister: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "write_group_remote_sregister: {}".format(err))

            msg = "ATSALL:{},{}{}={},{}".format(
                group_id, target_reg, bit_position, data, password)

        else:
            msg = "ATSALL:{},{}{}={}".format(
                group_id, target_reg, bit_position, data)

        return msg

    def get_all_local_sregister(self):
        """Get command to retrieve all local module S-Register.

        Returns:
            String with "AT+TOKDUMP".
        """
        return "AT+TOKDUMP"

    #################################################
    # Network control and configuration
    #################################################

    def scan_energy(self):
        """Get command to scan energy of all channels available to
            local module.

        Returns:
            String with "AT+ESCAN".
        """
        return "AT+ESCAN"

    def scan_pan(self):
        """Get command to scan for available PAN of all channels
            available to local module.

        Returns:
            String with "AT+PANSCAN"
        """
        return "AT+PANSCAN"

    def start_pan(self):
        """Get command to start a new PAN from local module.

        Returns:
            String with "AT+EN"
        """
        # Establish Personal Area Network
        return "AT+EN"

    def join_pan(self):
        """Get command to join in some PAN.

        This commands uses the link key to get network from Trust Centre
        and join in some PAN.

        Returns:
            String with "AT+JN"
        """
        return "AT+JN"

    def join_specific_pan(self, channel, pan_id):
        """Get command to join in specific PAN.

        This commands uses the link key to get network from Trust Centre
        and join in the pan using channel and PAN id as reference.

        Args:
            channel: ZigBee Chanell (11-26).
            pan_id: ZigBee PAN identifier (4 hexadecimal characters) or
                EUI64 format (16hexadecimal characters).

        Returns:
            String with "AT+JPAN:<channel>,<pan_id>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_zigbee_channel(channel)
            self.validate_zigbee_pan(pan_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "join_specific_pan: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "join_specific_pan: {}".format(err))

        return "AT+JPAN:" + str(channel) + "," + str(pan_id)

    def join_silent_pan(self, channel, tc_eui64, node_id, update_id=0):
        """Get command to silent join in specific PAN.

        "Silent" joining is joining via the commissioning method.

        All data required to enter the network is provided to the node, so
        that no joining procedure itself is required. The node will appear
        in the target network without any joining procedure given the
        supplied data is correct.

        The local node will become part of the network with the channel
        specified in <channel>, the trust centre EUI64 specified in
        <tc_eui64>, the node id of the network manager specified in
        <node_id>, the 8 bit network update ID specified in <update_id>.

        The network key is provided in S08, the trust centre link key is
        provided in S09, the PAN ID provided in S02 and the extended PAN ID
        provided in S03.

        It is assumed that the key-sequence-number of the network key
        is 0 when issuing this command.

        Args:
            channel: ZigBee Chanell (11-26).
            tc_eui64: ZigBee node mac address in EUI64 format.
            node_id: ZigBee node identifier (4 hexadecimal characters).
            update_id: network update ID (default=0).

        Returns:
            String with "AT+SJN:<channel>,<tc_eui64>,<node_id>,<update_id>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            hex_update_id = "{:02X}".format(update_id)
            self.validate_zigbee_channel(channel)
            self.validate_etrx3x_node_identifier(tc_eui64)
            self.validate_etrx3x_node_identifier(node_id)
            self.validate_update_id(hex_update_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "join_silent_pan: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "join_silent_pan: {}".format(err))

        return "AT+SJN:{},{},{},{}".format(
            channel, tc_eui64, node_id, hex_update_id)

    def leave_pan(self):
        """Get command to dissassociate local node from PAN.

        Returns:
            String with "AT+DASSL".
        """
        return "AT+DASSL"

    def remove_node(self, node_id):
        """Get command to dissassociate a remote node from PAN.

        Args:
            node_id: ZigBee node mac address in EUI64 format.

        Returns:
            String with "AT+DASSR:<node_id>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "remove_node: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "remove_node: {}".format(err))

        return "AT+DASSR:{}".format(node_id)

    def info_network(self):
        """Get command to retrieve connected PAN information.

        Returns:
            String with "AT+N?".
        """
        return "AT+N?"

    def neighbour_table(self, index, address):
        """Get command to retrieve an node neighbour table.

        Get neighbour table returns at most 3 entries of total neighbour
        table. If node contains more than 3 entries, you can set the index
        to access the others entries.

        Args:
            index: neighbour table entry index in decimal.
            address: ZigBee node MAC (EUI64 format), node id (4 hexadecimal
                characters) or address table index.

        Returns:
            String with "AT+NTABLE:<hex_index>,<address>". <hex_index> is the
            index converted in hexadecimal.

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_table_index(index)
            self.validate_etrx3x_node_identifier(address)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "neighbour_table: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "neighbour_table: {}".format(err))

        hex_index = "{:02X}".format(index)

        return "AT+NTABLE:{},{}".format(
            hex_index, address)

    def node_routing_rable(self, index, address):
        """Get command to retrieve a node routing table.

        Get routing table returns at most 3 entries of total neighbour
        table. If node contains more than 3 entries, you can set the index
        to access the others entries.

        Args:
            index: neighbour table entry index in decimal.
            address: ZigBee node MAC (EUI64 format), node id (4 hexadecimal
                characters) or address table index.

        Returns:
            String with "AT+NTABLE:<hex_index>,<address>". <hex_index> is the
            index converted in hexadecimal.

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_table_index(index)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "neighbour_table: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "neighbour_table: {}".format(err))

        hex_index = "{:02X}".format(index)

        return "AT+RTABLE:{},{}".format(
            hex_index, address)

    def node_get_id(self, node_id, index=None):
        """Get command to request (local or remote) node id (ZDO).

        Where <node_id> can be a node's EUI64, or node_id table entry
        and <index> is an optional index number.

        In case an index number is provided, an extended response is
        requested asking the remote device to list its associated
        devices (ie children).

        Sends a broadcast to obtain the specified Device's NodeID and
        optionally also elements of its associated devices list.

        Args:
            node_id: ZigBee node MAC (EUI64 format).
            index: neighbour table entry index in decimal (defaul=None).

        Returns:
            String with "AT+IDREQ:<node_id>[,<index>]".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(node_id, only_eui=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_get_id: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_get_id: {}".format(err))

        if(index is not None):
            try:
                self.validate_table_index(index)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "node_get_id: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "node_get_id: {}".format(err))

            hex_index = "{:02X}".format(index)

            msg = "AT+IDREQ:{},{}".format(node_id, hex_index)

        else:
            msg = "AT+IDREQ:{}".format(node_id)

        return msg

    def node_get_eui(self, address, node_id, index):
        """Get command to request (local or remote) node mac (ZDO).

        Where <node_id> can be a node's EUI64, or node_id table entry
        and <index> is an optional index number.

        In case an index number is provided, an extended response is
        requested asking the remote device to list its associated
        devices (ie children).

        Sends a unicast to obtain the specified device's EUI64 and
        optionally also elements of its associated devices list.

        Args:
            address: ZigBee node MAC (EUI64 format).
            node_id: ZigBee node network identifier (4 hexadecimal chars).
            index: neighbour table entry index in decimal.

        Returns:
            String with "AT+EUIREQ:<node_id>[,<index>]".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(
                address)
            self.validate_etrx3x_node_identifier(
                node_id, only_node_id=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_get_eui: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_get_eui: {}".format(err))

        if(index is not None):
            try:
                self.validate_table_index(index)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "node_get_eui: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "node_get_eui: {}".format(err))

            msg = "AT+EUIREQ:{},{},{}".format(
                address, node_id, index)
        else:
            msg = "AT+EUIREQ:{},{}".format(address, node_id)

        return msg

    def node_get_descriptor(self, address, node_id):
        """Get command to request (local or remote) node descriptor (ZDO).

        Args:
            address: ZigBee node MAC (EUI64 format).
            node_id: ZigBee node identifier (4 hexadecimal characters).

        Returns:
            String with "AT+NODEDESC:<address>,<node_id>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(address, only_eui=True)
            self.validate_etrx3x_node_identifier(node_id, only_node_id=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_get_descriptor: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_get_descriptor: {}".format(err))

        return "AT+NODEDESC:{},{}".format(
            address, node_id)

    def node_get_power_descriptor(self, address, node_id):
        """Get command to request (local or remote) node power descriptor.

        Args:
            address: ZigBee node MAC (EUI64 format).
            node_id: ZigBee node identifier (4 hexadecimal characters).

        Returns:
            String with "AT+POWERDESC:<address>,<node_id>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(address, only_eui=True)
            self.validate_etrx3x_node_identifier(node_id, only_node_id=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_get_power_descriptor: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_get_power_descriptor: {}".format(err))

        return "AT+POWERDESC:{},{}".format(
            address, node_id)

    def node_get_active_ep_list(self, address, node_id):
        """Get command to request (local or remote) node active endpoints.

        Args:
            address: ZigBee node MAC (EUI64 format).
            node_id: ZigBee node identifier (4 hexadecimal characters).

        Returns:
            String with "AT+ACTEPDESC:<address>,<node_id>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_etrx3x_node_identifier(node_id, only_node_id=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_get_active_ep_list: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_get_active_ep_list: {}".format(err))

        return "AT+ACTEPDESC:{},{}".format(
            address, node_id)

    def node_end_point_descriptor(self, address, node_id, endpoint_number):
        """Get command to request (local or remote) node endpoint description.

        Args:
            address: ZigBee node MAC (EUI64 format).
            node_id: ZigBee node identifier (4 hexadecimal chars).
            endpoint_number: is the endpoint identifier (2 hexadecimal chars).

        Returns:
            String with "AT+SIMPLEDESC:<address>,<node_id>,<endpoint_number>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(address, only_eui=True)
            self.validate_etrx3x_node_identifier(node_id, only_node_id=True)
            self.validate_endpoint_number(endpoint_number)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_end_point_descriptor: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_end_point_descriptor: {}".format(err))

        return "AT+SIMPLEDESC:{},{},{}".format(
            address, node_id, endpoint_number)

    def find_node_by_descriptor(
        self, profile_id, in_cluster_list,
            out_cluster_list):
        """Get command to find nodes which match a specific descriptor.

        Where <profile_id> required profile id of the device being searched
        for followed by a specification of required input and output clusters.

        If a remote node has a matching profile id and matches at least one of
        the specified clusters it will respond to this broadcast listing the
        matching endpoint(s).

        Args:
            profile_id: profile identifier in ZigBee profile list
                (Telegesis is C091).
            in_cluster_list: list of input cluster id (4 hexadecimal chars)
                separeted with ",".
            out_cluster_list: list of output cluster id (4 hexadecimal chars)
                separeted with ",".

        Returns:
            String with "AT+MATCHREQ:<profile_id>,<num_in_cluster>,
                <in_cluster_list>,<num_out_cluster>,<out_cluster_list>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_profile_id(profile_id)
            self.validate_cluster_id_list(in_cluster_list)
            self.validate_cluster_id_list(out_cluster_list)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "find_node_by_descriptor: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "find_node_by_descriptor: {}".format(err))

        in_cluster_len = len(in_cluster_list)

        if(in_cluster_len == 0):
            in_cluster = "{:02X}".format(in_cluster_len)
        else:
            in_cluster = "{:02X},{}".format(
                in_cluster_len, ",".join(in_cluster_list))

        out_cluster_len = len(out_cluster_list)

        if(out_cluster_len == 0):
            out_cluster = "{:02X}".format(out_cluster_len)
        else:
            out_cluster = "{:02X},{}".format(
                out_cluster_len, ",".join(out_cluster_list))

        return "AT+MATCHREQ:{},{},{}".format(
            profile_id, in_cluster, out_cluster)

    def node_announce_presence(self):
        """Get command to announce local node in the PAN.

        Returns:
            String with "AT+ANNCE".
        """
        return "AT+ANNCE"

    def node_set_source_route(self, node_id_list):
        """Get command to set source routing from local node to remote node.

        Args:
            node_id_list: node id (4 hexadecimal chars) separeted with
                ",".

        Returns:
            String with "AT+SR:<node_id>,<node_id>,...".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_node_list(node_id_list)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_set_source_route: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_set_source_route: {}".format(err))

        return "AT+SR:{}".format(",".join(node_id_list))

    def node_find_route_to_device(self, address):
        """Get command to find source routing from local node to remote node.

        Args:
            address: node address in mac EUI64 format or node id format
                (4 hexadecimal chars).

        Returns:
            String with "AT+FNDSR:<address>".

        Raises:
            TypeError: invalid input arguments data type.
            ValueError: invalid input arguments data content.
        """
        try:
            self.validate_etrx3x_node_identifier(address, only_eui=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "node_find_route_to_device: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "node_find_route_to_device: {}".format(err))

        return "AT+FNDSR:{}".format(address)

    def poll_data(self):
        """Get command to poll data from parent node.

        This command is used only in enddevice (ZED, SED, MED).

        Returns:
            String with "AT+POLL".
        """
        return "AT+POLL"

    def node_rejoin(self, with_security=True):
        """Get command to rejoin in the network.

        This command will make local node to leave (AT+DASSL) and join
        the PAN (AT+JN).

        Args:
            with_security: flag to set rejoin with pre-configured security
                keys and flags.

        Returns:
            String with "AT+REJOIN:<with_security>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        if(isinstance(with_security, bool) is False):
            raise ETRX3xATCommandException(
                "node_rejoin: invalid with_security data type {}".format(
                    with_security))

        if(with_security is True):
            b = 1
        else:
            b = 0

        return "AT+REJOIN:{}".format(b)

    def scan_network(self, num_hops=0):
        """Get command to scan nodes in the PAN.

        All Telegesis devices which are up to <num_hops> hops away
        from local module are listed.

        If <num_hops> is "01" only direct neighbours will reply and
        <num_hops> is "00" will search the entire network.

        Args:
            num_hops: number of hops away from local node (defaul=None).

        Returns:
            String with "AT+SN:<num_hops>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_hops(num_hops)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "scan_network: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "scan_network: {}".format(err))

        if(num_hops > 0):
            msg = "AT+SN:{}".format(num_hops)
        else:
            msg = "AT+SN"

        return msg

    def update_network_key(self):
        """Get command to update network key.

        Updates the Network Key with a new random or key.

        Returns:
            String with "AT+KEYUPD".
        """
        return "AT+KEYUPD"

    def node_become_tc(self):
        """Get command to turn local node into Trust Centre node.

        Local Device takes over the Trust Centre. Can only be used if no
        other device in the network is Trust Centre (i.e. the network has
        been started in distributed Trust Centre mode)

        Use on Router that established the PAN in distributed TC Mode.

        Can only be used if Network has been started in distributed
        Trust Centre mode (bit 9 of S0A set).

        Returns:
            String with "AT+BECOMETC".
        """

        return "AT+BECOMETC"

    def node_become_network_manager(self):
        """Get command to turn local node into Network Manager node.

        Local Device takes over role of Network Manager. By default the
        COO is the Network Manager, but any other router in the network
        can take over this responsibility.

        The Network Manager can change the radio channel and the PAN ID.

        Use on Router.

        Returns:
            String with "AT+BECOMENM".
        """
        return "AT+BECOMENM"

    def network_change_channel(self, channel=None):
        """Get command to change PAN channel.

        Use on Network Manager.

        Args:
            channel: channel value from 11 to 26 in hexadecimal.

        Returns:
            String with "AT+CCHANGE".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        if(channel is not None):
            try:
                self.validate_zigbee_channel(channel)

            except ValueError as err:
                raise ETRX3xATCommandException(
                    "network_change_channel: {}".format(err))

            except TypeError as err:
                raise ETRX3xATCommandException(
                    "network_change_channel: {}".format(err))

            msg = "AT+CCHANGE:{:02X}".format(channel)

        else:
            msg = "AT+CCHANGE"

        return msg

    def get_address_table(self):
        """Get command to retrieve local address table.

        Returns:
            String with "AT+ATABLE".
        """
        return "AT+ATABLE"

    def set_address_table_entry(self, entry, node_id, eui64):
        """Get command to set local address table entry.

        Where 'entry' is the entry number of the address table entry which
        is to be written.

        If the NodeID is unknown, the NodeID must be substituted
        with "FFFF".

        Args:
            entry: integer entry index of atable.
            node_id: ZigBee node identifier (4 hexadecimal characters).
            eui64: ZigBee node MAC (EUI64 format).

        Returns:
            String with "AT+ASET:<entry>,<node_id>,<eui64>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_table_index(entry)
            self.validate_etrx3x_node_identifier(eui64, only_eui=True)
            self.validate_etrx3x_node_identifier(node_id, only_node_id=True)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "set_address_table_entry: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "set_address_table_entry: {}".format(err))

        return "AT+ASET:{:02X},{},{}".format(entry, node_id, eui64)

    def get_multicast_table(self):
        """Get command to retrieve local multicast table.

        For Multicasts to be displayed using the MCAST prompt,
        endpoint 01 must be selected as the target endpoint.

        Returns:
            String with "AT+MTABLE".
        """
        return "AT+MTABLE"

    def set_multicast_table_entry(self, entry, multicast_id, endpoint):
        """Get command to set local multicast table entry.

        Where 'entry' is the index number of the multicast-table entry
        which is to be written.

        For the AT-Command interface operation the endpoint should
        always be set to 01.

        Args:
            entry: integer entry index of multicast table.
            multicast_id: ZigBee node identifier (4 hexadecimal characters).
            endpoint: endpoint identifier (2 hexadecimal chars).

        Returns:
            String with "AT+MSET:<entry>,<multicast_id>,<endpoint>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_table_index(entry)
            self.validate_multicast_id(multicast_id)
            self.validate_endpoint_number(endpoint)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "set_multicast_table_entry: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "set_multicast_table_entry: {}".format(err))

        return "AT+MSET:{:02X},{},{}".format(entry, multicast_id, endpoint)

    def send_broadcast(self, data, num_hops=0):
        """Get command send broadcast message.

        Note: Use broadcasts sparingly! The ZigBee specification only allows
        any node to repeat or originate up to 8 broadcasts in every 8
        second interval. Broadcasts use a lot of bandwidth.


        A maximum of 82 bytes are sent (with attached EUI only 74 bytes).
        The response OK shows successful transmission.

        Successful transmission does not guarantee successful reception.

        To make sure data has been received by a specific node use
        a unicast message.

        Only neighbours which are up to <num_hops> hops away will receive
        the broadcast.

        If <num_hops> = 01 only direct neighbours will receive the broadcast.

        If <num_hops> = 00 the entire network will (max. 30 hops).

        For binary data, use AT+BCASTB.

        Args:
            num_hops: integer number of hops value ranging from 00 to 30.
                00 wil transmit to entire network (same as 30 hops).
            data: data to be sent as payload message (max: 74 bytes).

        Returns:
            String with "AT+BCAST:<num_hops>,<data>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_hops(num_hops)
            self.validate_message_payload(data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_broadcast: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_broadcast: {}".format(err))

        return "AT+BCAST:{:02X},{}".format(num_hops, data)

    def send_broadcast_binary(self, binary, num_hops=0):
        """Get command to send broadcast binary message.

        Same as send_broadcast but it has diferente process to send
        binary data.

        This command is particularly useful if the data may contain
        <CR> and <Backspace> parameters characters.

        Args:
            num_hops: number of hops value range from 00 to 30. 00
                wil transmit to entire network (same as 30 hops).
            binary: binary data with length range from 00 to 74 bytes.

        Returns:
            String with "AT+BCASTB:<data_length>,<num_hops>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_hops(num_hops)
            self.validate_message_payload(binary)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_broadcast_binary: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_broadcast_binary: {}".format(err))

        data_length = len(binary)

        return "AT+BCASTB:{:02X},{}\r{}".format(data_length, num_hops, binary)

    def send_unicast(self, address, data):
        """Get command to send broadcast binary message.

        Unicasts can be addressed either by referencing the recipient's
        EUI64, NodeID or an entry in the address table.

        The maximum payload is 82 bytes. It is reduced by 8 bytes when
        appending the EUI to the network header (default) and also it is
        reduced by 2 bytes per hop in case a source route is known.
        The latter event can neither be suppressed nor foreseen.

        Up to 10 unicasts may be in flight at one time Unicasts can
        travel up to 30 hops

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            data: data to be sent as payload message (max: 74 bytes).

        Returns:
            String with "AT+UCAST:<address>,<data>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_message_payload(data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_unicast: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_unicast: {}".format(err))

        return "AT+UCAST:{},{}".format(address, data)

    def send_unicast_binary(self, address, binary):
        """Get command to send broadcast binary message.

        Unicasts can be addressed either by referencing the recipient's
        EUI64, NodeID or an entry in the address table.

        The maximum payload is 82 bytes. It is reduced by 8 bytes when
        appending the EUI to the network header (default) and also it is
        reduced by 2 bytes per hop in case a source route is known.
        The latter event can neither be suppressed nor foreseen.

        Up to 10 unicasts may be in flight at one time Unicasts can
        travel up to 30 hops

        This command is particularly useful if the data may contain
        <CR> and <Backspace> characters.

        The ACK and/or NACK prompt can be disabled in S0E.

        NOTE: binary is sent to Serial Service in
        "AT+UCASTB:<len>,<node_id>\r<binary>".

        Serial service will handle binary data and send it to Zigbee network
        properly.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            binary: data to be sent as payload message with size <data_length>.

        Returns:
            String with "AT+UCASTB:<data_length>,<address>\r<binary>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_message_payload(binary)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_unicast_binary: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_unicast_binary: {}".format(err))

        data_length = "{:02X}".format(len(binary))

        return "AT+UCASTB:{},{}\r{}".format(
            data_length, address, binary)

    def send_track(self, address, data, message_id, seq, trace_level):
        """Get command to send Unicast message with track on Serial Service.

        This is an special command of SG Gateway Serial Service.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            data: data to be sent as payload message (max: 74 bytes).
            message_id: message id controled by service or source origin.
            seq: trace sequence number.
            trace_level: trace level to send notification. Values range from 0
                to 2.

        Returns:
            String with "AT+SENDTRACK:<address>,<data>,<message_id>,
                <seq>,<trace_level>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_message_payload(data)
            self.validate_track_message_id(message_id)
            self.validate_track_sequence_number(seq)
            self.validate_track_level(trace_level)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_track: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_track: {}".format(err))

        return "AT+SENDTRACK:{},{},{},{},{}\r".format(
            address, data, message_id, seq, trace_level)

    def send_track_binary(self, address, binary, message_id, seq, trace_level):
        """Get command to send Unicast binary message with track on
        Serial Service.

        This is an special command of SG Gateway Serial Service.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            binary: data to be sent as payload message with size up to
                74 bytes.
            message_id: message id controled by service or source origin.
            seq: trace sequence number.
            trace_level: trace level to send notification. Values range from 0
                to 2.

        Returns:
            String with "AT+SENDTRACKB:<data_length>,<address>,<data>,
                <message_id>,<seq>,<trace_level>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_message_payload(binary)
            self.validate_track_message_id(message_id)
            self.validate_track_sequence_number(seq)
            self.validate_track_level(trace_level)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_track_binary: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_track_binary: {}".format(err))

        data_length = "{:02X}".format(len(binary))

        return "AT+SENDTRACKB:{},{},{},{},{}\r{}".format(
            data_length, address, message_id, seq, trace_level, binary)

    def send_track_notify(self, message_id, seq, trace_code):
        """Get notification to send track message.

        This is an special notification of SG Gateway Serial Service.

        Args:
            message_id: message id controled by service or source origin.
            seq: trace sequence number.
            trace_code: trace code defined in track list code
                (see SG Gateway documentation for mode details).

        Returns:
            String with "\r\nSENDTRACK:<message_id>,<seq>,<trace_code>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_track_message_id(message_id)
            self.validate_track_sequence_number(seq)
            # TODO(rubens): make trace_code validation

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_track_notify: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_track_notify: {}".format(err))

        return "\r\nSENDTRACK:{},{},{}\r\n".format(
            message_id, seq, trace_code)

    def send_sink(self, data):
        """Get command to send Unicast message to sink node.

        When bit 8 of S10 is set, if a sink cannot be reached for three
        consecutive transmissions the sink is assumed unavailable and a
        new one is sought.

        The ACK and/or NACK prompt can be disabled in S0E.

        When attaching the node's EUI64 to the network frame the maximum
        payload reduces to 74 bytes. The maximum payload is 82 bytes.
        It is reduced by 8 bytes when appending the EUI to the network
        header (default) and also it is reduced by 2 bytes per hop in case
        a source route is known.

        The latter event can neither be suppressed nor foreseen.

        Args:
            data: data to be sent as payload message (max: 74 bytes).

        Returns:
            String with "AT+SCAST:<data>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_message_payload(data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_track_notify: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_track_notify: {}".format(err))

        return "AT+SCAST:{}".format(data)

    def send_sink_binary(self, binary):
        """Get command to send Unicast binary message to sink node.

        Same description of send_sink.

        Args:
            binary: binary data length ranging from 00 to 74 bytes.

        Returns:
            String with "AT+SCASTB:<binary>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_message_payload(binary)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_sink_binary: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_sink_binary: {}".format(err))

        data_length = "{:02X}".format(len(binary))

        # TODO(rubens): add payload content, such as send_unicast_binary
        return "AT+SCASTB:{}\r{}".format(data_length, binary)

    def find_sink(self):
        """Get command to search for sink node.

        Search for a sink on the network by sending a broadcast
        causing all sinks to reply.

        By default, if a sink is already known and no better sink is
        found, no prompt will be displayed.

        A sink which is already known can be found at index 05 of
        the address table.

        Returns:
            String with "AT+SSINK".
        """
        return "AT+SSINK"

    def send_multicast(self, num_hops, mcast_table_index, data):
        """Get command to send message to multicast.

        Up to 82 bytes are sent to the multicast group <mcast_table_index>.

        Instead of a 16-bit multicast ID an 8 bit binding table entry
        can be specified.

        Args:
            num_hops: number of hops value ranging from 00 to 30.
                00 wil transmit to entire network (same as 30 hops).
            mcast_table_index: multicast index or multicast entry bind id.
            data: data to be sent as payload message (max: 74 bytes).

        Returns:
            String with "AT+MCAST:<num_hops>,<mcast_table_index>,<data>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_hops(num_hops)
            self.validate_table_index(mcast_table_index)
            self.validate_message_payload(data)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_multicast: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_multicast: {}".format(err))

        return "AT+MCAST:{:02X},{:02X},{}".format(
            num_hops, mcast_table_index, data)

    def send_multicast_binary(self, num_hops, mcast_table_index, binary):
        """Get command to send message to multicast.

        Up to 82 bytes are sent to the multicast group <mcast_table_index>.

        Instead of a 16-bit multicast ID an 8 bit binding table entry
        can be specified.

        Args:
            num_hops: number of hops value ranging from 00 to 30.
                00 wil transmit to entire network (same as 30 hops).
            mcast_table_index: multicast index or multicast entry bind id.
            binary: binary data with length from 0 to 74 bytes.

        Returns:
            String with "AT+MCAST:<num_hops>,<mcast_table_index>,<data>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_hops(num_hops)
            self.validate_table_index(mcast_table_index)
            self.validate_message_payload(binary)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_multicast_binary: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_multicast_binary: {}".format(err))

        data_length = "{:02X}".format(len(binary))

        return "AT+MCASTB:{},{},{}\r{}".format(
            data_length, num_hops, mcast_table_index, binary)

    def enable_data_mode(self, address):
        """Get command enable data mode with remote node (serial link mode).

        Opening a serial link to end devices will result in a limited data
        rate which depends on the polling interval of the child.

        In Data mode all prompts are disabled.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).

        Returns:
            String with "AT+DMODE:<address>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "enable_data_mode: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "enable_data_mode: {}".format(err))

        return "AT+DMODE:{}".format(address)

    def disable_data_mode(self):
        """Get command disaable data mode with remote node (serial link
        mode).

        Returns:
            String with "+++".
        """
        return "+++"

    def play_tune(self, address):
        """Play tune on remote node.

        Plays a tune on a remote devboard if the Beeper is connected.

        Useful to identify remote nodes. See devkit manual for details
        about connecting a buzzer to the ETRXn.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).

        Returns:
            String with "AT+IDENT:<address>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "play_tune: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "play_tune: {}".format(err))

        return "AT+IDENT:{}".format(address)

    def send_broadcast_raw_data(self, binary):
        """Get command to send broadcast message in raw data.

        Can be useful to quickly exchange bulk data with neighbouring
        node. The application needs to handle addressing, error
        checking, retries and acknowledgements.

        AT+RDATAB generates broadcasts so any node may only originate
        up to 8 broadcasts in every 8 second interval.

        Broadcasts use a lot of bandwidth.

        End Devices do not receive raw data.

        Raw data will only travel one hop.

        Use with great care. Raw data messages are not ZigBee-compliant and
        may even leak into other PANs.

        Args:
            binary: binary data with length from 0 to 74 bytes.

        Returns:
            String with "AT+RDATAB:<binary>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_message_payload(binary)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "send_broadcast_raw_data: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "send_broadcast_raw_data: {}".format(err))

        data_length = "{:02X}".format(len(binary))

        return "AT+RDATAB:{}\r{}".format(data_length, binary)

    #####################################
    # Binding Management (ETRX3 only)
    #####################################
    def get_local_binding_table(self):
        """Get command to retrieve local binding device table.

        Returns:
            String with "AT+LBTABLE".
        """
        return "AT+LBTABLE"

    def set_local_binding_table_entry(
        self, bind_type, local_endpoint, cluster_id, address,
            remote_endpoint):
        """Get command to set local binding table entry.

        The new binding is created in the next available free binding table
        entry.

        Args:
            bind_type: is the type of binding as shown:
                1 = Unicast Binding with EUI64 and remote EP specified
                2 = Many to one Binding with EUI64 and remote EP Specified
                3 = Multicast Binding with Multicast ID Specified
            local_endpoint: local endpoint identifier (2 hexadecimal chars).
            cluster_id: cluster id
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            remote_endpoint: remote endpoint identifier (2 hexadecimal chars).

        Returns:
            String with "AT+BSET:<bind_type>,<local_endpoint>,<cluster_id>,
                <address>,<remote_endpoint>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_bind_type(bind_type)
            self.validate_endpoint_number(local_endpoint)
            self.validate_cluster_id(cluster_id)
            self.validate_etrx3x_node_identifier(address)
            self.validate_endpoint_number(remote_endpoint)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "set_local_binding_table_entry: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "set_local_binding_table_entry: {}".format(err))

        return "AT+BSET:{},{},{},{},{}".format(
            bind_type, local_endpoint, cluster_id, address, remote_endpoint)

    def clear_local_binding_table(self, entry):
        """Get command to clear local binding table entry.

        Where XX is the entry number of the binding table entry which
        is to be cleared.

        To keep the numbering of the local binding table in-line with
        the numbering of the remote binding table all remaining entries
        are moved to the beginning of the table.

        See entry value in LBTABLE or BTABLE command

        Args:
            entry: local binding table entry number.

        Returns:
            String with "AT+BCLR:<entry>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_table_index(entry)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "clear_local_binding_table: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "clear_local_binding_table: {}".format(err))

        return "AT+BCLR:{}".format(entry)

    def get_binding_table(self, entry_index, address):
        """Get command to get remote binding table entry.

        Where <entry_index> is the start index of the remote Binding
        table and <address> can be the remote node's EUI64, NodeID or
        address/binding table entry.

        Note: Also the local node can be the target of this command
        (e.g. use address table entry FF as the address)

        Args:
            entry_index: binding table entry index.
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).

        Returns:
            String with "AT+BTABLE:<entry_index>,<address>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_table_index(entry_index)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "get_binding_table: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "get_binding_table: {}".format(err))

        return "AT+BTABLE:{:02X},{}".format(
            entry_index, address)

    def set_binding_on_remote_node(
        self, address, bind_type, source_address, source_endpoint,
            cluster_id, destiny_address, destiny_endpoint="01"):
        """Get command to set remote binding table entry.

        "source" and "destination" are defined from the viewpoint of the
        remote device.

        The local node can also be the target of this command
        (e.g. use address table entry FF as the address).

        All parameters must have exactly the correct number of characters.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            bind_type: integer with type of binding as shown:
                1 = Multicast Binding with Multicast ID
                    specified in <destiny_address>.
                3 = Unicast Binding with destination EUI64 in OK
                    <destiny_address>.
            source_address: the EUI64 of the Source
            source_endpoint: the source Endpoint
            cluster_id: the cluster ID on the source displayed Device
            destiny_address: the EUI64 or 16-bit multicast ID, depending
                on <bind_type>
            destiny_endpoint: only in Mode 3

        Returns:
            String with "AT+BIND:<address>,<bind_type>,<source_address>,
                <source_endpoint>,<cluster_id>,<destiny_address>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_bind_type(bind_type)
            self.validate_etrx3x_node_identifier(source_address)
            self.validate_endpoint_number(source_endpoint)
            self.validate_cluster_id(cluster_id)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "set_binding_on_remote_node: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "set_binding_on_remote_node: {}".format(err))

        if(bind_type == 1):
            try:
                self.validate_etrx3x_node_identifier(
                    destiny_address, only_node_id=True)

            except ValueError:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: invalid destiny MulticastId"
                    " value for bind type {}".format(bind_type))

            except TypeError:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: invalid destiny MulticastId"
                    " data type for bind type {}".format(bind_type))

            msg = "AT+BIND:{},{},{},{},{},{}".format(
                address,
                bind_type,
                source_address,
                source_endpoint,
                cluster_id,
                destiny_address)

        else:  # mode 3 - Unicast binding
            try:
                self.validate_etrx3x_node_identifier(
                    destiny_address, only_eui=True)

            except ValueError:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: invalid destiny EUI64"
                    " address value for bind type {}".format(bind_type))

            except TypeError:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: invalid destiny EUI64"
                    " address data type for bind type {}".format(bind_type))

            if(destiny_endpoint is not None):
                try:
                    self.validate_endpoint_number(destiny_endpoint)

                except ValueError:
                    raise ETRX3xATCommandException(
                        "set_binding_on_remote_node: destiny endpoint value"
                        " for bind type {}".format(bind_type))

                except TypeError:
                    raise ETRX3xATCommandException(
                        "set_binding_on_remote_node: destiny endpoint data"
                        " type for bind type {}".format(bind_type))

                msg = "AT+BIND:{},{},{},{},{},{},{}".format(
                    address,
                    bind_type,
                    source_address,
                    source_endpoint,
                    cluster_id,
                    destiny_address,
                    destiny_endpoint)

            else:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: destiny endpoint not defined"
                    " for bind type {}".format(bind_type))

        return msg

    def remove_binding_on_remote_node(
        self, address, bind_type, source_address, source_endpoint,
            cluster_id, destiny_address, destiny_endpoint="01"):
        """Get command to remove remote binding table entry.

        "source" and "destination" are defined from the viewpoint of the
        remote device.

        The local node can also be the target of this command
        (e.g. use address table entry FF as the address).

        All parameters must have exactly the correct number of characters.

        Args:
            address: ZigBee node MAC (EUI64 format), ZigBee node id
                (4 hexadecimal chars) or address table index
                (2 hexadecimal chars).
            bind_type: is the type of binding as shown:
                1 = Multicast Binding with Multicast ID SEQ:01
                    specified in <destiny_address>.
                3 = The destination endpoint prompt is displayed.
                3 = Unicast Binding with destination EUI64 in OK
                    <destiny_address>.
            source_address: the EUI64 of the Source
            source_endpoint: the source Endpoint
            cluster_id: the cluster ID on the source displayed Device
            destiny_address: the EUI64 or 16-bit multicast ID, depending
                on <type>
            destiny_endpoint: only in Mode 2

        Returns:
            String with "AT+UNBIND:<address>,<bind_type>,<source_address>,
                <source_endpoint>,<cluster_id>,<destiny_address>,
                <destiny_endpoint>".

        Raises:
            ETRX3xATCommandException: invalid input arguments data
                type or data value.
        """
        try:
            self.validate_etrx3x_node_identifier(address)
            self.validate_bind_type(bind_type)
            self.validate_etrx3x_node_identifier(source_address)
            self.validate_endpoint_number(source_endpoint)

        except ValueError as err:
            raise ETRX3xATCommandException(
                "remove_binding_on_remote_node: {}".format(err))

        except TypeError as err:
            raise ETRX3xATCommandException(
                "remove_binding_on_remote_node: {}".format(err))

        if(bind_type == 1):
            try:
                self.validate_etrx3x_node_identifier(
                    destiny_address, only_node_id=True)

            except ValueError:
                raise ETRX3xATCommandException(
                    "remove_binding_on_remote_node: invalid destiny"
                    " MulticastId value for bind type {}".format(
                        bind_type))

            except TypeError:
                raise ETRX3xATCommandException(
                    "remove_binding_on_remote_node: invalid destiny"
                    " MulticastId data type for bind type {}".format(
                        bind_type))

            msg = "AT+UNBIND:{},{},{},{},{},{}".format(
                address,
                bind_type,
                source_address,
                source_endpoint,
                cluster_id,
                destiny_address)

        else:  # mode 3 - Unicast binding
            try:
                self.validate_etrx3x_node_identifier(
                    destiny_address, only_eui=True)

            except ValueError:
                raise ETRX3xATCommandException(
                    "remove_binding_on_remote_node: invalid destiny EUI64"
                    " address value for bind type {}".format(bind_type))

            except TypeError:
                raise ETRX3xATCommandException(
                    "remove_binding_on_remote_node: invalid destiny EUI64"
                    " address data type for bind type {}".format(bind_type))

            if(destiny_endpoint is not None):
                try:
                    self.validate_endpoint_number(destiny_endpoint)

                except ValueError:
                    raise ETRX3xATCommandException(
                        "remove_binding_on_remote_node: destiny endpoint value"
                        " for bind type {}".format(bind_type))

                except TypeError:
                    raise ETRX3xATCommandException(
                        "remove_binding_on_remote_node: destiny endpoint data"
                        " type for bind type {}".format(bind_type))

                msg = "AT+UNBIND:{},{},{},{},{},{},{}".format(
                    address,
                    bind_type,
                    source_address,
                    source_endpoint,
                    cluster_id,
                    destiny_address,
                    destiny_endpoint)

            else:
                raise ETRX3xATCommandException(
                    "set_binding_on_remote_node: destiny endpoint not defined"
                    " for bind type {}".format(bind_type))

        return msg

    def parse_error(self, code):
        """Parse ZigBee Telegesis ETRX3x error code and return the error
        message.

        Args:
            code: erro code in 2 hexadecimal format.

        Returns:
            Error message that represents the code. Return unknow message
            for not mapped codes in Telegesis ETRX3x.
        """

        if(code == "00"):
            return "Everything OK - Success"

        elif(code == "01"):
            return "Couldn't poll Parent because of Timeout"

        elif(code == "02"):
            return "Unknown command"

        elif(code == "04"):
            return "Invalid S-Register"

        elif(code == "05"):
            return "Invalid parameter"

        elif(code == "06"):
            return "Recipient could not be reached"

        elif(code == "07"):
            return "Message was not acknowledged"

        elif(code == "08"):
            return "No sink known"

        elif(code == "09"):
            return "Address Table entry is in use and cannot be modified"

        elif(code == "0A"):
            return "Message could not be sent"

        elif(code == "0B"):
            return "Local node is not sink"

        elif(code == "0C"):
            return "Too many characters"

        elif(code == "0E"):
            return "Background Scan in Progress (Please wait and try again)"

        elif(code == "0F"):
            return "Fatal error initialising the network"

        elif(code == "10"):
            return "Error bootloading"

        elif(code == "12"):
            return "Fatal error initialising the stack"

        elif(code == "18"):
            return "Node has run out of Buffers"

        elif(code == "19"):
            return "Trying to write read-only register"

        elif(code == "1A"):
            return "Data Mode Refused by Remote Node"

        elif(code == "1B"):
            return "Connection Lost in Data Mode"

        elif(code == "1C"):
            return "Remote node is already in Data Mode"

        elif(code == "20"):
            return "Invalid password"

        elif(code == "25"):
            return "Cannot form network"

        elif(code == "27"):
            return "No network found"

        elif(code == "28"):
            return "Operation cannot be completed if node is part of a PAN"

        elif(code == "2C"):
            return "Error leaving the PAN"

        elif(code == "2D"):
            return "Error scanning for PANs"

        elif(code == "33"):
            return "No response from the remote bootloader"

        elif(code == "34"):
            return "Target did not respond during cloning"

        elif(code == "35"):
            return "Timeout occurred during xCASTB"

        elif(code == "39"):
            return "MAC Transmit Queue is Full"

        elif(code == "6C"):
            return "Invalid Binding Index"

        elif(code == "70"):
            return "Invalid Operation"

        elif(code == "72"):
            return "More than 10 unicast messages were in flight at the"\
                " same time"

        elif(code == "74"):
            return "Message too long"

        elif(code == "80"):
            return "ZDP Invalid Request Type"

        elif(code == "81"):
            return "ZDP Device not Found"

        elif(code == "82"):
            return "ZDP Invalid Endpoint"

        elif(code == "83"):
            return "ZDP Not Active"

        elif(code == "84"):
            return "ZDP Not Supported"

        elif(code == "85"):
            return "ZDP Timeout"

        elif(code == "86"):
            return "ZDP No Match"

        elif(code == "87"):
            return "ZDP Table Full"

        elif(code == "88"):
            return "ZDP No Entry"

        elif(code == "89"):
            return "ZDP No Descriptor"

        elif(code == "91"):
            return "Operation only possible if connected to a PAN"

        elif(code == "93"):
            return "Node is not part of a Network"

        elif(code == "94"):
            return "Cannot join network"

        elif(code == "96"):
            return "Mobile End Device Move to new Parent Failed"

        elif(code == "98"):
            return "Cannot join ZigBee 2006 Network as Router"

        elif(code == "A1"):
            return "More than 8 broadcasts were sent within 8 seconds"

        elif(code == "AB"):
            return "Trying to join, but no beacons could be heard"

        elif(code == "AC"):
            return "Network key was sent in the clear when trying to"\
                " join secured"

        elif(code == "AD"):
            return "Did not receive Network Key"

        elif(code == "AE"):
            return "No Link Key received"

        elif(code == "AF"):
            return "Preconfigured Key Required"

        elif(code == "C5"):
            return "NWK Already Present"

        elif(code == "C7"):
            return "NWK Table Full"

        elif(code == "C8"):
            return "NWK Unknown Device"

        else:
            return "Error Unkown. Code: {}".format(code)

    def parse_sr(self, data):
        """Parse SR prompt message.

        Args:
            data: SR prompt message with parameters.

        Returns:
            Source routing path as a list of node ids.
        """
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        fields = rdata.split(":")[1].split(",")
        return fields

    def parse_newnode(self, data):
        """Parse NEWNODE prompt message.

        Args:
            data: NEWNODE prompt message with parameters.

        Returns:
            List with node data:
                [ node_type, node_eui64, node_id ]
        """
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")
        fields = rdata.split(":")[1].split(",")

        return fields

    def parse_node_presence(self, data):
        """Parse node presence (FFD, SED, MED, ZED) prompt message.

        Args:
            data: node presence prompt message with parameters.

        Returns:
            List with node data:
                [ node_type, node_eui64, node_id ]
        """
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")
        fields = rdata.split(":")[1].split(",")

        return fields

    def parse_cast(self, data):
        """Parse xCast (UCAST, MCAST) prompt message.

        Args:
            data: xCast prompt message with parameters.

        Returns:
            List with node data:
                [ node_eui64, data_length, payload, rssi, lqi ]

            If RSSI and LQI of UCAST messages are not enabled they will have
            'None' value.
        """
        # xCAST:mac,data_length=data

        # ":".join is used to avoid split application protocol messages
        splitData = ":".join(data.split(":")[1:])
        sdata = splitData.split(",")

        if(len(sdata) == 1):
            # Handle ETRX3x BUG
            # Notifications come without data length
            # ex: UCAST:000D6F0000BA19DB1A=22102014185513R0S1EA000324

            eui = sdata[0].split("=")[0]
            payload = sdata[1].split("=")[1]
            data_length = str(len(data))

        else:  # if(len(sdata) == 2):
            eui = sdata[0]
            # Incoming ex: UCAST:000D6F0000BA19DB1A,08=AUTO,1,0

            # ",".join is used to avoid split application protocol message
            n_data = ",".join(sdata[1:])

            data_length = int(n_data.split("=")[0], 16)

            # Set data from the correct length
            data_content = "=".join(n_data.split("=")[1:])
            payload = data_content[0:data_length]

            lqi = None
            rssi = None

            if(data_content[data_length] == ","):
                signal_content = data_content[data_length:].split(",")
                rssi = signal_content[1]

                if(len(signal_content[2]) > 2):
                    # Avoid '\r\n' at the end of content
                    lqi = signal_content[2][0:2]
                else:
                    lqi = signal_content[2]

        fields = [eui, data_length, payload, rssi, lqi]

        return fields

    def parse_jpan(self, data):
        """Parse JPAN prompt response content.

        Args:
            data: JPAN prompt content.

        Returns:
            List with started PAN data:
                [pan channel, pan id, pan eid]
        """
        pan = []

        # Remove return chars
        rdata = data.replace("\r", "")

        # Check for empty response
        if rdata.find("JPAN:") == -1:
            return None

        # Remove strings
        rdata = rdata.replace("JPAN:", "")
        rdata = rdata.replace("OK", "")

        # Split string based on newline char
        sdata = rdata.split("\n")

        for i in sdata:
            if i != "":
                pan = i.split(",")

        return pan

    def parse_swrite(self, data):
        """Parse SWRITE prompt message.

        SWRITE prompt message is used to confirm write on remote
        S-Register.

        Args:
            data: SWRITE message with parameters.

        Returns:
            List with register write status data:
                [ node_id, node_eui, error_code ]
        """
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        # SWRITE:<node_id>,<eui>,<error_code>
        sdata = rdata.split(":")[1].split(",")

        node_id = sdata[0]
        eui = sdata[1]
        error_code = sdata[2]

        fields = [node_id, eui, error_code]

        return fields

    def parse_sread(self, data):
        """Parse SREAD prompt message.

        Args:
            data: SREAD message with parameters.

        Returns:
            List with register read data:
                [ node_id, node_eui, register, error_code, value]
        """
        # SREAD:<node_id>,<eui>,<register>,<error_code>=<value>

        # If error code is diferrent from ZERO, '=<value>' don't come
        # in notification message.
        rdata = data.replace("\n", "").replace("\r", "")

        sdata = rdata.split(":")[1].split(",")

        node_id = sdata[0]
        eui = sdata[1]
        register = sdata[2]
        content = sdata[3].split("=")

        if(len(content) == 1):
            error_code = content[0]
            value = None
        else:
            error_code = content[0]
            value = content[1]

        fields = [node_id, eui, register, error_code, value]

        return fields

    def parse_addrresp(self, data):
        """Parse ADDRRESP prompt message.

        Args:
            data: ADDRRESP message with parameters.

        Returns:
            List with node address data:
                [ node_id, node_eui, error_code ]
        """
        # AddrResp:<error_code>,<node_id>,<eui>
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        sdata = rdata.split(":")[1].split(",")

        error_code = sdata[0]
        node_id = sdata[1]
        eui = sdata[2]

        # Response format
        response = [node_id, eui, error_code]

        return response

    def parse_rx(self, data):
        """Parse RX prompt message.

        Args:
            data: RX message with parameters.

        Returns:
            List with node address data:
                [ node_id, node_eui, error_code ]
        """
        # AddrResp:<error_code>,<node_id>,<eui>
        sdata = data.split(":")[1].split(",")

        # EUI64 is only shown if included in network frame header
        if(len(sdata) == 7):
            # Get eui without start '\r\n'
            eui = sdata[0]
            node_id = sdata[1]
            profile_id = sdata[2]
            dst_ep = sdata[3]
            src_ep = sdata[4]
            cluster_id = sdata[5]
            payload_size = int(sdata[6], 16)
            payload = ":".join(data.split(":")[2])[0:payload_size]

        else:
            # Get eui without start '\r\n'
            eui = None
            node_id = sdata[0]
            profile_id = sdata[1]
            dst_ep = sdata[2]
            src_ep = sdata[3]
            cluster_id = sdata[4]
            payload_size = int(sdata[5], 16)
            payload = ":".join(data.split(":")[2])[0:payload_size]

        # Response format
        response = [
            eui, node_id, profile_id, dst_ep, src_ep,
            cluster_id, payload
        ]

        return response

    def parse_raw(self, data):
        """Parse RAW prompt message.

        Args:
            data: RAW message with parameters.

        Returns:
            List with send track data:
                [ request_id, sequence, track_code ]
        """
        # RAW:<rssi>,<binary>
        sdata = data.split(":")[1].split(",")

        rssi = int(sdata[0])
        binary = ",".join(sdata[1:])[0:-2]

        # Response format
        response = [rssi, binary]

        return response

    def parse_sink(self, data):
        """Parse SINK prompt message.

        Args:
            data: SINK message with parameters.

        Returns:
            List with selected new SINK data:
                [ node_id, node_eui]
        """
        # AddrResp:<error_code>,<node_id>,<eui>
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        sdata = rdata.split(":")[1].split(",")

        eui = sdata[0]
        node_id = sdata[1]

        # Response format
        response = [node_id, eui]

        return response

    def parse_sendtrack(self, data):
        """Parse SENDTRACK prompt message.

        Args:
            data: SENDTRACK message with parameters.

        Returns:
            List with send track data:
                [ request_id, sequence, track_code ]
        """
        # SENDTRACK:<request_id>,<sequence>,<track_code>
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        sdata = rdata.split(":")[1].split(",")

        request_id = sdata[0]
        sequence = sdata[1]
        track_code = sdata[2]

        # Response format
        response = [request_id, sequence, track_code]

        return response

    def parse_sg_error_message(self, data):
        """Parse SG error code.

        Args:
            data: SG error code with parameters.

        Returns:
            Tuple with error_code and description.
        """
        # ERROR:<error_code>[,<desc>]
        rdata = data.replace("\n", "")
        rdata = rdata.replace("\r", "")

        sdata = rdata.split(":")[1].split(",")

        if(len(sdata) == 1):
            if(len(sdata[0]) == 2):
                # Parse code erro for SG Error code table
                # New error code convert the 2 hexa chars
                # to 4 decimal chars

                # This is used only to avoid error with old
                # serial service versions
                error_code = int("1" + str(int(sdata[0], 16)).zfill(3))
            else:
                error_code = int(sdata[0])
            desc = ""
        elif (len(sdata) == 2):
            if(len(sdata[0]) == 2):
                # Parse code erro for SG Error code table
                # New error code convert the 2 hexa chars
                # to 4 decimal chars

                # This is used only to avoid error with old
                # serial service versions
                error_code = int("1" + str(int(sdata[0])).zfill(3))
            else:
                error_code = int(sdata[0])
            desc = sdata[1]

        return error_code, desc

    def parse_node_route_status(self, code):
        """Parse ZigBee node routing entry status.

        Args:
            code: ZigBee routing entry status.

        Returns:
            String that represents the code.
        """

        if(code == "00"):
            response = "ACTIVE"
        elif(code == "01"):
            response = "DISCOVERY_UNDERWAY"
        elif(code == "02"):
            response = "DISCOVERY_FAILED"
        elif(code == "03"):
            response = "INACTIVE"
        elif(code == "04"):
            response = "VALIDATION_UNDERWAY"
        else:
            response = "RESERVED"

        return response

    def parse_current_power_mode(self, value):
        """Parse current power mode on PowerDesc AT command.

        Args:
            value: current power mode value.

        Returns:
            String for value described in ZigBee specification at
                2.3.2.4.1.
        """

        if(value == 0x0):
            return "receiver synchronized with the receiver on"\
                " when idle sub-field of the node descriptor"

        elif(value == 0x1):
            return "receiver comes on periodically as defined by"\
                " the node power descriptor"

        elif(value == 0x2):
            return "receiver comes on when stimulated, e.g. by a"\
                " user pressing a button"

        else:
            return "reserved"

    def parse_available_power_source(self, value):
        """Parse avaliable power source on PowerDesc AT command.

        Args:
            value: avaliable power source value.

        Returns:
            String for value described in ZigBee specification at
                2.3.2.4.1.
        """
        if(value == 0x0):
            return "constant (mains) power"

        elif(value == 0x1):
            return "rechargeable battery"

        elif(value == 0x2):
            return "disposable battery"

        else:
            return "reserved"

    def parse_current_power_source(self, value):
        """Parse current power source on PowerDesc AT command.

        Args:
            value: current power source value.

        Returns:
            String for value described in ZigBee specification at
                2.3.2.4.1.
        """
        if(value == 0x0):
            return "constant (mains) power"

        elif(value == 0x1):
            return "rechargeable battery"

        elif(value == 0x2):
            return "disposable battery"

        else:
            return "reserved"

    def parse_current_power_level(self, value):
        """Parse current power level on PowerDesc AT command.

        Args:
            value: current power level value.

        Returns:
            String for value described in ZigBee specification at
                2.3.2.4.1.
        """
        if(value == 0x0):
            return "critical"

        elif(value == 0x4):
            return "33%"

        elif(value == 0x8):
            return "66%"

        elif(value == 0xC):
            return "100%"

        else:
            return "reserved"

    #####################################
    # ETRX3x Module AT commands response
    #####################################
    def ok_response(self):
        return "\r\nOK\r\n"

    def at_tokdump_response(self, node_sreg_dict):
        local_regs_message = "\r\n"
        for reg in sorted(node_sreg_dict):
            local_regs_message += "{}:{}\r\n".format(
                reg, node_sreg_dict[reg])

        return local_regs_message

    def ati_response(self, local_node_eui):
        version = "R309C"
        ati_response_message = \
            "\r\nTelegesis ETRX357-Fake\r\n{}\r\n{}\r\n".format(
                version, local_node_eui)

        return ati_response_message

    def at_n_response(
        self, local_node_type, pan_channel, pan_power, pan_id,
            pan_eid):
        at_n_response_message = "\r\n+N={},{},{},{},{}\r\n".format(
            local_node_type, pan_channel, pan_power, pan_id,
            pan_eid)

        return at_n_response_message

    def at_n_nopan_response(self):
        return "+N=NoPAN"

    def ats_response(self, reg, value, with_reg=False):
        if(with_reg is False):
            local_sreg_message = "\r\n{}\r\n".format(value)
        else:
            local_sreg_message = "\r\nS{}={}\r\n".format(reg.upper(), value)

        return local_sreg_message

    def at_atable_response(self, address_table):
        """
        address_table = {
            "active": <bool>,
            "node_id": <node_id>,
            "node_eui": <node_eui>
        }
        """
        atable_message = "\r\nNo. | Active |  ID  | EUI\r\n"
        for i, address in enumerate(address_table):
            if(address["active"] is True):
                active_flag = "Y"
            else:
                active_flag = "N"
            atable_message += "{}  |   {}    | {} |{}\r\n".format(
                hex(i)[2:].zfill(2), active_flag,
                address["node_id"], address["node_eui"])
        atable_message += "\r\n"

        return atable_message

    def at_ntable_response(self, node_id, error_code, index, neighbour_table):
        """
        address_table = {
            "type": <node_type_str>, - "FFD", "COO", "RFD"
            "node_id": <node_id>,
            "node_eui": <node_eui>,
            "signal": <int_lqi> - from 0 to 255
        }
        """
        # TODO(rubens): add parameters validation
        ntable_message = "\r\nNTable:{},{}\r\n".format(node_id, error_code)
        ntable_message += "Length:{:02X}\r\n".format(len(neighbour_table))

        if(index >= 0):
            ntable = neighbour_table[index:index+3]

            if(len(ntable) > 0):
                ntable_message +=\
                    "No. | Dev |       EUI        |  ID  | LQI\r\n"

                for i, nnode in enumerate(neighbour_table[index:index + 3]):
                    ntable_message += "{:02X}. | {} | {} | {} | {:02X}\r\n".\
                        format(
                            (index + i), nnode["type"], nnode["node_eui"],
                            nnode["node_id"], nnode["signal"])

        return ntable_message

    def panscan_notification(
        self, channel, pan_id, pan_eid, zb_stack, joinable, rssi=None,
            lqi=None):
        # TODO(rubens): add parameters validation

        if(rssi is None and lqi is None):
            notify = "\r\n+PANSCAN:{},{},{},{},{}\r\n".format(
                channel, pan_id, pan_eid, zb_stack, joinable)
        else:
            notify = "\r\n+PANSCAN:{},{},{},{},{},{},{}\r\n".format(
                channel, pan_id, pan_eid, zb_stack, joinable, rssi, lqi)

        return notify

    def ucast_notification(self, eui, payload, rssi=None, lqi=None):
        # TODO(rubens): add parameters validation
        if(rssi is not None and lqi is not None):
            notify = "\r\nUCAST:{},{:02X}={},{:02X},{:02X}\r\n".format(
                eui, len(payload), payload, rssi, lqi
            )
        else:
            notify = "\r\nUCAST:{},{:02X}={}\r\n".format(
                eui, len(payload), payload)

        return notify

    def sread_notification(
            self, node_id, node_eui, reg, error_code, value=None):

        if(value is not None):
            notify = "\r\nSREAD:{},{},{},{}={}\r\n".format(
                node_id, node_eui, reg, error_code, value)
        else:
            notify = "\r\nSREAD:{},{},{},{}\r\n".format(
                node_id, node_eui, reg, error_code)

        return notify

    def seq_response(self, seq_number):
        return "\r\nSEQ:{:02X}\r\n".format(seq_number)

    def ack_response(self, seq_number):
        return "\r\nACK:{:02X}\r\n".format(seq_number)

    def nack_response(self, seq_number):
        return "\r\nNACK:{:02X}\r\n".format(seq_number)

    def error_response(self, error_code):
        return "\r\nERROR:{}\r\n".format(error_code)
