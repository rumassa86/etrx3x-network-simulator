#!/usr/bin/env python

import re
import json


# Auxliar functions to validade input parameters
def validate_node_identifier(node_identifier):
    """Validate a ZigBee node id or node EUI identifier.

    Args:
        node_identifier: ZigBee node id or node EUI as string or unicode
            format.

    Returns:
        True if it is a valid node identifier otherwise False.
    """
    if((type(node_identifier) != str) and (type(node_identifier) != unicode)):
        return False

    if(len(node_identifier) == 4):
        # test node_id format with 4 Hexas
        if (check_node_id_format(node_identifier) is True):
            return True
        else:
            return False

    if(len(node_identifier) == 16):
        # test node_eui format with 16 Hexas
        if (check_node_eui_format(node_identifier) is True):
            return True
        else:
            return False
    return False


def check_node_id_format(node_id):
    """Check for a ZigBee node id.

    Args:
        node_id: ZigBee node identifier (4 hexadecimal chars).

    Returns:
        True if it is a valid node id otherwise False.
    """
    node_mask = "^[0-9a-fA-F]{4}"

    if((type(node_id) != str) and (type(node_id) != unicode)):
        return False

    if(len(node_id) > 4):
        return False

    if (re.match(node_mask, node_id) is not None):
        return True
    else:
        return False


def check_node_eui_format(node_eui):
    """Check for a ZigBee node EUI.

    Args:
        node_eui: ZigBee node EUI (16 hexadecimal chars).

    Returns:
        True if it is a valid node id otherwise False.
    """
    if((type(node_eui) != str) and (type(node_eui) != unicode)):
        return False

    if(len(node_eui) > 16):
        return False

    node_mask = "^[0-9a-fA-F]{16}"
    if (re.match(node_mask, node_eui) is not None):
        return True
    else:
        return False


def validate_host(host):
    """Validate IP address or DNS hostname format.

    Args:
        host: IP address or DNS hostname in string format.

    Returns:
        True if it is a valid hostname or IP address otherwise False.
    """
    ip_addr_mask = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"\
        "|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    hostname_mask = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*"\
        "[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"

    if (re.search(ip_addr_mask, host) is not None):
        return True
    elif (re.search(hostname_mask, host) is not None):
        return True

    return False


def validate_port(port):
    """Validate TCP port valu and range.

    Args:
        port: port integer value from 0 to 65534.

    Returns:
        True if it is a valid TCP port otherwise False.
    """
    try:
        port_int = int(port)
    except:
        return False

    if(port_int >= 0 and port_int < 65535):
        return True
    else:
        return False


def validate_network_address(addr_string):
    """Validate Network Address in format "<host>:<port>" format.

    Args:
        addr_string: string address in format "<host>:<port>"

    Returns:
        True if addr_string has correcty format.

    Raises:
        ValueError for invalid addr_string format, host or IP value or
        TCP port value.
    """
    addr = addr_string.split(":")

    if(len(addr) != 2):
        raise ValueError(
            "Invalid address format. Should be <host>:<port> format:"
            " Should be: {!r}".format(addr_string)
        )

    host = addr[0]

    if(validate_host(host) is False):
        raise ValueError(
            "Invalid target host: {!r}".format(host)
        )

    try:
        port = int(addr[1])

    except ValueError:
        raise ValueError(
            "Invalid value of target TCP port: {}".format(addr[1]))

    if(validate_port(port) is False):
        raise ValueError(
            "Invalid target TCP port: {!r}".format(port)
        )


def validate_zigbee_key(key):
    """Validate ZigBee Network Key.

    Args:
        key: string of 128 bits key in 32 hexadecimal chars.

    Returns:
        True if it is a valid key otherwise False.
    """
    key_mask = "^[0-9a-fA-F]{32}"
    if(type(key) == long):
        key = hex(key)[2:].replace("L", "")

    if((type(key) != str) and (type(key) != unicode)):
        return False

    if(len(key) == 32):
        if (re.match(key_mask, key) is not None):
            return True
        else:
            return False

    return False


def validate_zigbee_channel_range(channel):
    """Validate ZigBee Channel range value.

    Args:
        channel: ZigBee Channel value.

    Returns:
        True if ZigBee channel value is valid or False if it is invalid.
    """
    if((channel > 10) and (channel < 27)):
        return True
    else:
        return False


def validate_sg_serial_number(sn):
    """Validate Smartgreen Serial Number device format

    Args:
        sn: integer serial number ranging from 0 to 9999999999999

    Returns:
        True if it is a valid serial number of False otherwise.
    """
    if((sn >= 0) and (sn <= 9999999999999)):
        return True
    else:
        return False


def validate_sg_device_version(version):
    """Validate Smartgreen Device Version format

    Args:
        version: version in string format:
            <major>.<minor>[.<revision>]

    Returns:
        True if it is a valid device version or False otherwise.
    """
    dev_version = "^\d+\.\d+(\.\d+)?$"

    if(type(version) != str) and (type(version) != unicode):
        return False

    if(re.match(dev_version, version) is not None):
        return True
    else:
        return False


def validate_sg_device_type(dev_type):
    """Validate Smartgreen Device type.

    Args:
        dev_type: device type string.

    Returns:
        True if it is a valid device type of False otherwise.
    """
    dev_type_list = [
        "SGCORTE",
        "SGCORTEFLAT",
        "SGIP",
        "SGIPF",
        "SGBT",
        "SGHIBRIDO",
        "TELEGESIS",
        "SGCON",
        "SGROUTER",
        "SGRDM",
        "SGWEG",
        "SGUSB",
        "UNKNOW"
    ]

    if((type(dev_type) != str) and (type(dev_type) != unicode)):
        return False

    if(len(dev_type) > 13):
        return False

    if(dev_type in dev_type_list):
        return True
    else:
        return False


def validate_filename(filename):
    """Validate filename format.

    The filename should contains characters, numbers, underscore '_' or minus
    '-', a dot char '.' and optional file extension with three or four
    characters.

    Example: "test.cfg", "test.conf", "test_error.conf"

    Args:
        filename: input filename string.

    Returns:
        True if filename is valid or False if it is not valid.
    """
    # \w = [a-zA-Z0-9_]
    pattern = "^[\w,\s-]+(\.[A-Za-z]{3,4})?$"

    result = re.match(pattern, filename)

    if((type(filename) != str) and (type(filename) != unicode)):
        return False

    if(result is None):
        return False
    else:
        return True


def validate_directory_path(dir_path):
    """Validate directory path.

    Args:
        dir_path: directory unix path.

    Returns:
        True if directory path is valid or False if it is not valid.
    """
    pattern = "^(.*/*)([^/]*)$"

    # TODO(rubens): check for invalid directory characters, such as
    #   '[', ']', '(', ')', '%', '_'
    # pattern = "[\/.]*(\/*[a-zA-Z0-9_\s-]*)"

    if((type(dir_path) != str) and (type(dir_path) != unicode)):
        return False

    result = re.match(pattern, dir_path)

    if(result is None):
        return False
    else:
        return True


def parse_json(json_message):
    """Parse string JSON to python dictionary structure.

    Args:
        json_message: JSON in string format.

    Returns:
        Dictionary with JSON structure.
    """
    try:
        if((type(json_message) != str) and (type(json_message) != unicode)):
            raise ValueError("json_message must be string")

        decoded = json.loads(json_message)

        return decoded

    except (ValueError, KeyError, TypeError):
        # TODO(rubens): create exception for parse json error
        return None


def convert_to_string(dict_msg):
    """Convert Python dictionary to JSON plain text format.

        Args:
            dict_msg: dictionary structure.

        Returns:
            String with JSON plain text with content of dict_msg.
    """
    try:
        json_msg = json.dumps(dict_msg)

        return json_msg
    except:
        # TODO(rubens): create exception for convert dict to json
        return None


def get_host_port(addr_string):
    """Validate and build address tuple based on input address string.

   Args:
        addr_string: string address in format "<host>:<port>"

    Returns:
        Tuple with network address in format (<host>, <port>).

    Raises:
        ValueError for invalid addr_string format, host or IP value or
        TCP port value.
    """
    if((type(addr_string) != str) and (type(addr_string) != unicode)):
        raise ValueError("addr_string must be string")

    try:
        validate_network_address(addr_string)

        addr = addr_string.split(":")

        host = addr[0]
        port = int(addr[1])

        return (host, port)

    except ValueError as err:
        raise err
