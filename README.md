# Python Development Challenge

## Goal

Develop a Python program that can add and read a text comment into a packet of a PCAPNG file.

## Functionality

### Adding a Comment

**Inputs:**
- **PCAPNG file**: Path to the input PCAPNG file.
- **String of text**: The comment to be added.
- **Packet number**: The index (1-based) of the packet to which the comment should be added.

**Outputs:**
- A new PCAPNG file with the comment inserted in the specified packet.

### Reading a Packet

**Inputs:**
- **PCAPNG file**: Path to the PCAPNG file.
- **Packet number**: The index (1-based) of the packet to be read.

**Outputs:**
- A JSON text printed to the console, containing the details of the specified packet.
