#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pty
import re

master, slave = pty.openpty()

slave_name = os.ttyname(slave)
master_name = os.ttyname(master)
print("Slave : {}".format(slave_name))
print("Master: {}".format(master_name))

print("Reading data from {!r}".format(slave_name))

store_data = ""
command_list = []
at_detected = False

echo_enabled = False

local_node_type = "FFD"
local_node_eui = "74BE000000000000"
local_node_id = "1234"

pan_channel = "26"
pan_power = "-07"
pan_id = "3F65"
pan_eid = "0C119647931B9284"

ok_message = "\r\nOK\r\n"

local_node_sregs = {
    "00": "8000",
    "01": "{}".format(pan_power),
    "02": "0000",
    "03": "{}".format(pan_channel),
    "04": "{}".format(local_node_eui),
    "05": "{}".format(local_node_id),
    "06": "000D6F0002544E9D",
    "07": "AB76",
    "08": "<hidden>",
    "09": "<hidden>",
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
    "46": "001B7FB1",
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

tokdump_message = "\r\n"
for reg in sorted(local_node_sregs):
    tokdump_message += "{}:{}\r\n".format(reg, local_node_sregs[reg])

ati_message = "\r\nTelegesis ETRX357-Fake\r\nR309C\r\n{}\r\n".format(
    local_node_eui)


def error_message(error_code):
    return "\r\nERROR:{}\r\n".format(error_code)


while True:
    data = os.read(master, 1)

    if(echo_enabled is True):
        os.write(master, data)

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
            os.write(master, ok_message)
            store_data = ""
        else:
            # Clear stored data for invalid char
            store_data = ""

    elif(len(store_data) >= 3):
        if(data == "\r"):
            if(store_data == "ati"):
                os.write(master, ati_message + ok_message)

            elif(store_data == "ats"):
                # return error message
                # 05 = invalid_parameter
                # 02 = invalid_command
                os.write(master, error_message("05"))

            elif(re.match("ats[0-9a-f]", data) is None):
                os.write(master, error_message("05"))

            elif(re.match("ats[0-9a-f]{2}", store_data)):
                # atsXX = get local s register
                pass

            elif(re.match("ats[0-9a-f]{3}", store_data)):
                # atsXXP = get local s register
                pass

            elif(store_data == "atz"):
                os.write(master, ok_message)

            elif(store_data == "at+n"):
                at_n_message = "\r\n+N={},{},{},{},{}\r\n".format(
                    local_node_type, pan_channel, pan_power, pan_id,
                    pan_eid)

                os.write(master, at_n_message + ok_message)

            elif(store_data == "at+tokdump"):
                os.write(master, tokdump_message + ok_message)
                store_data = ""

            else:
                # 02 = Invalid comand
                os.write(master, error_message("02"))

            # Clear stored data command
            store_data = ""

        else:
            store_data += data

    else:
        # Clear stored data for invalid char
        store_data = ""

print("Terminating ETRX3x Network simulator")
