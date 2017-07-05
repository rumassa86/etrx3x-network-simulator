# Telegesis ETRX3x Network Simulator

Telegesis ETRX3x Network Simulator for test programs and services build on top of ETRX3x modules.

These project can be used to simulate a ZigBee Network created by ETRX3x modules that can be accessed by AT Commands defined in [TG-ETRXn-Commands](https://www.silabs.com/documents/public/reference-manuals/TG-ETRXn-Commands.pdf).

You can set the network topology defining the nodes, node's links, node's etrx3x configurations, 

# Running

To run the simulator:

```
$ python -m lib.etrx3x_sim
```

It will show the serial port that can be used to communicate with simulator (see *slave*):

```
Starting ETRX3x Simulator
Slave : /dev/pts/18
Master: /dev/ptmx
Starting write thread queue
```

Currently, the network contains a hard coded network structure with two nodes (ED00010000000000 - COO and ED00010000000001 - FFD).

To get help of simulator:

```
$ python -m lib.etrx3x_sim -h
```

# TODO

* read the input network topology and nodes ETRX3x configuration as JSON file;
* Implement ATREMS for write SRegisters;
* Implement MCU behaviors to send data to local module (to test performance of hugh amount of incoming messages);
* Add code documentation based on Sphinx;
* Add automated tests (unit, integrated);
