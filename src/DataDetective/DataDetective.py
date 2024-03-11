#!/usr/bin/env python3

""" Unlock the story hidden in data. Your digital investigation partner.

Created By  : Franck FERMAN @franckferman, @branoodle, @MimiChan, @s4tb0y and @yametersa.
Created Date: 11/03/24
Version     : 1.0.0 (11/03/24)
"""

import argparse
import subprocess
import sys
from typing import Tuple

from pyfiglet import Figlet


def banner_text() -> None:
    """Display the script banner."""
    banner = Figlet(font='cybermedium')
    print(banner.renderText('DataDetective'))


def check_image_validity(image_path: str) -> Tuple[bool, str]:
    """
    Check the validity of the provided disk image.

    Args:
        image_path: The path to the disk image.

    Returns:
        A tuple containing a boolean indicating success or failure,
        and a string message describing the outcome.
    """
    try:
        subprocess.check_output(['mmls', image_path], stderr=subprocess.STDOUT)
        return True, "The specified image is valid and contains partitions."
    except subprocess.CalledProcessError as e:
        return False, f"Error validating image: {e.output.decode()}"


def list_partitions(image_path: str) -> Tuple[bool, str]:
    """
    List the partitions of the provided disk image.

    Args:
        image_path: The path to the disk image.

    Returns:
        A tuple containing a boolean indicating success or failure,
        and a string message describing the outcome or the partitions list.
    """
    try:
        output = subprocess.check_output(['mmls', image_path], text=True)
        return True, output
    except subprocess.CalledProcessError as e:
        return False, f"Failed to list partitions: {e}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Unlock the story hidden in data - Your digital investigation partner.")
    parser.add_argument("-i", "--image", help="Path to the disk image file.", required=True)
    parser.add_argument("--check-image", action="store_true", help="Check if the disk image is valid and contains partitions.")
    parser.add_argument("--show-partitions", action="store_true", help="Show partitions in the disk image without further analysis.")

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    banner_text()

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
        else:
            success, message = check_image_validity(args.image)
            print(message)
            if not success:
                sys.exit(1)
    else:
        print("Error: -i/--image is required.")
        sys.exit(1)


if __name__ == "__main__":
    main()
