import os
import json
import sys
import logging

from pcapng.blocks import EnhancedPacket, SectionHeader, InterfaceDescription
from pcapng import FileScanner,FileWriter
from typing import List, Optional

def read_pcapng_blocks(pcapng_file: str) -> (Optional[SectionHeader], List[InterfaceDescription], List[EnhancedPacket]):
    """
    Reads and parses PCAPNG blocks from a file.

    Args:
        pcapng_file: The path to the PCAPNG file.

    Returns:
        A tuple containing the SectionHeader block, a list of InterfaceDescription blocks,
        and a list of EnhancedPacket blocks.
    """
    logging.info(f"Reading PCAPNG file: {pcapng_file}")
    if not os.path.isfile(pcapng_file):
        logging.error(f"File not found: {pcapng_file}")
        raise FileNotFoundError(f"The file {pcapng_file} does not exist.")


    with open(pcapng_file, 'rb') as f:
        scanner = FileScanner(f)
        blocks = list(scanner)

    section_header = None
    interface_descriptions = []
    packet_blocks = []

    for block in blocks:
        if isinstance(block, SectionHeader):
            section_header = block
        elif isinstance(block, InterfaceDescription):
            interface_descriptions.append(block)
        elif isinstance(block, EnhancedPacket):
            packet_blocks.append(block)

    if section_header is None:
        logging.error("No SectionHeaderBlock found in the input file.")
        raise ValueError("No SectionHeaderBlock found in the input file.")

    logging.info(f"Found {len(interface_descriptions)} interface description blocks and {len(packet_blocks)} packet blocks.")
    return section_header, interface_descriptions, packet_blocks

def add_comment_to_packet(pcapng_file: str, output_file: str, packet_number: int, comment: str) -> None:
    """
    Adds a comment to a specific packet in a PCAPNG file and saves the result to a new file.

    Args:
        pcapng_file: The path to the input PCAPNG file.
        output_file: The path to the output PCAPNG file with the modified packet.
        packet_number: The index (1-based) of the packet to which the comment should be added.
        comment: The comment to add to the packet.
    """
    logging.info(f"Adding comment to packet {packet_number} in file {pcapng_file}.")
    section_header, _, packet_blocks = read_pcapng_blocks(pcapng_file)

    if not (1 <= packet_number <= len(packet_blocks)):
        logging.error(f"Packet number {packet_number} is out of range.")
        raise IndexError("Packet number out of range.")

    packet_blocks[packet_number - 1].options['opt_comment'] = comment
    logging.info(f"Comment added: '{comment}'")

    with open(output_file, 'wb') as f:
        writer = FileWriter(f, section_header)
        for block in packet_blocks:
            writer.write_block(block)

    logging.info(f"Modified PCAPNG file saved to {output_file}")


def read_packet_from_pcapng(pcapng_file: str, packet_number: int) -> None:
    """
    Reads and prints details of a specific packet from a PCAPNG file.

    Args:
        pcapng_file: The path to the PCAPNG file.
        packet_number: The index (1-based) of the packet to read.
    """
    logging.info(f"Reading packet {packet_number} from file {pcapng_file}.")
    _, _, packet_blocks = read_pcapng_blocks(pcapng_file)

    if not (1 <= packet_number <= len(packet_blocks)):
        logging.error(f"Packet number {packet_number} is out of range.")
        raise IndexError("Packet number out of range.")

    packet = packet_blocks[packet_number - 1]
    packet_info = {
        'packet_number': packet_number,
        'captured_len': packet.captured_len,
        'packet_len': packet.packet_len,
        'data': packet.packet_data.hex(),
        'comment': packet.options.get('opt_comment', None)
    }

    print(json.dumps(packet_info, indent=4))


def main():
    # Configure logging to output to stdout
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Example usage
    input_pcapng_file = "data/stratosphere_capture_0x7.pcapng"
    output_pcapng_file = "output/stratosphere_capture_0x7_with_comment.pcapng"
    packet_number = 1
    comment_text = "This is a comment for packet 1"

    # Check if input file exists
    if not os.path.isfile(input_pcapng_file):
        logging.error(f"Error: The input file '{input_pcapng_file}' does not exist.")
        return

    try:
        add_comment_to_packet(input_pcapng_file, output_pcapng_file, packet_number, comment_text)

        read_packet_from_pcapng(output_pcapng_file, packet_number)

    except ValueError as e:
        print(f"ValueError: {e}")
    except IndexError as e:
        print(f"IndexError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
