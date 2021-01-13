# Telegesis ETRX3x Network Simulator

Telegesis ETRX3x Network Simulator for test programs and services build on top of ETRX3x modules.

These project can be used to simulate a ZigBee Network created by ETRX3x modules that can be accessed by AT Commands defined in [TG-ETRXn-Commands](https://www.silabs.com/documents/public/reference-manuals/TG-ETRXn-Commands.pdf).

You can set the network topology defining the nodes, node's links, node's etrx3x configurations,

# Dependencies

* Python3 (3.5+)

# Running

The ETRX3x simulator request a terminal serial from the system and return a pair of serial ports (Slave and Master). For external communication you can use a serial program to connection into it.

## Running Simulator

To run the simulator using `simple_network.json` ZigBee Network toplogy:

```
$ python -m lib.etrx3x_sim test/simple_network.json
```

It will show the serial port that can be used to communicate with simulator (see *Follow*):

```
Starting ETRX3x Simulator
Follow: /dev/pts/0
Main  : /dev/ptmx
Starting write thread queue
```

## Running Serial terminal

You can use any Serial program to connect into it such as Picocom, Minicom, Miniterm, etc.

To connect it into the Simulator _follow_ port (in this tutorial is _/dev/pts/0_) using Picocom, do:

```
$ picocom /dev/pts/0
```

Note: it is not necessary to set baudrate.

# _TODO_ List

- [X] Read the input network topology and ETRX3x nodes configuration;
- [X] Add ATREMS for write SRegisters;
- [ ] Add firmware (MCU behaviors for send data to local module to test performance of incoming messages
- [ ] Add code documentation based on Sphinx
- [ ] Add automated tests
