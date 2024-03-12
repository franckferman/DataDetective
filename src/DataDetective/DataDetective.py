#!/usr/bin/env python3

""" Unlock the story hidden in data. Your digital investigation partner.

Created By  : Franck FERMAN @franckferman, @branoodle, @MimiChan, @s4tb0y and @yametersa.
Created Date: 11/03/24
Version     : 1.0.1 (12/03/24)
"""

import argparse
import re
import subprocess
import sys
from typing import Tuple

from pyfiglet import Figlet


def display_banner() -> None:
    """Display the script banner using a cybermedium font."""
    banner = Figlet(font='cybermedium')
    print(banner.renderText('DataDetective'))


def check_image_validity(image_path: str) -> Tuple[bool, str]:
    """
    Verify the validity of the specified disk image by checking if it has partitions.

    Args:
        image_path: The file path to the disk image.

    Returns:
        A tuple of a boolean indicating whether the check was successful, and a message.
    """
    try:
        subprocess.check_output(['mmls', image_path], stderr=subprocess.STDOUT)
        return True, "The specified image is valid and contains partitions."
    except subprocess.CalledProcessError as e:
        return False, f"Error validating image: {e.output.decode()}"


def list_partitions(image_path: str) -> Tuple[bool, str]:
    """
    List the partitions within the specified disk image, verifying its validity first.

    Args:
        image_path: The file path to the disk image.

    Returns:
        A tuple of a boolean indicating whether the listing was successful, and the output message.
    """
    valid, message = check_image_validity(image_path)
    if not valid:
        return False, message

    try:
        output = subprocess.check_output(['mmls', image_path], text=True)
        return True, output
    except subprocess.CalledProcessError as e:
        return False, f"Failed to list partitions: {e}"


def find_basic_data_partition_offset(image_path: str) -> Tuple[bool, int]:
    """
    Find the offset for the 'Basic data partition' within the specified disk image.

    Args:
        image_path: The file path to the disk image.

    Returns:
        A tuple of a boolean indicating whether the offset was found, and the offset value.
    """
    success, output = list_partitions(image_path)
    if not success:
        return False, 0

    regex = re.compile(r'\s*\d+:\s*\d+\s+(\d+)\s+\d+\s+\d+\s+.*Basic data partition.*')

    for line in output.splitlines():
        match = regex.match(line)
        if match:
            return True, int(match.group(1))
    return False, 0


def list_partition_files(image_path: str, offset: int) -> Tuple[bool, str]:
    """
    List the files within a partition specified by its offset in the disk image.

    Args:
        image_path: The file path to the disk image.
        offset: The offset of the partition within the disk image.

    Returns:
        A tuple of a boolean indicating whether the file listing was successful, and the output message.
    """
    try:
        output = subprocess.check_output(['fls', '-o', str(offset), image_path], text=True)
        return True, output
    except subprocess.CalledProcessError as e:
        return False, f"Failed to list files: {e}"


def main() -> None:
    """Main function to process command-line arguments and execute actions."""
    parser = argparse.ArgumentParser(description="Unlock the story hidden in data - Your digital investigation partner.")
    parser.add_argument("-i", "--image", help="Path to the disk image file.", required=True)
    parser.add_argument("--check-image", action="store_true", help="Check if the disk image is valid and contains partitions.")
    parser.add_argument("--show-partitions", action="store_true", help="Show partitions in the disk image without further analysis.")
    parser.add_argument("--show-files", action="store_true", help="Show files in the 'Basic data partition' of the disk image.")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    display_banner()

    if args.image:
        if args.check_image and args.show_partitions:
            print("Error: --check-image and --show-partitions cannot be used together.")
            sys.exit(1)
        elif args.check_image:
            success, message = check_image_validity(args.image)
            print(message)
            sys.exit(0 if success else 1)
        elif args.show_partitions:
            success, message = list_partitions(args.image)
            print(message)
            sys.exit(0 if success else 1)
        elif args.show_files:
            success, offset = find_basic_data_partition_offset(args.image)
            if not success:
                print("Failed to find 'Basic data partition'.")
                sys.exit(1)
            success, message = list_partition_files(args.image, offset)
            print(message)
            sys.exit(0 if success else 1)
        else:
            success, message = check_image_validity(args.image)
            print(message)
            if not success:
                sys.exit(1)
    else:
        print("No valid action specified. Please use one of the provided arguments.")
        sys.exit(1)


if __name__ == "__main__":
    main()
