#!/usr/bin/env python3
"""
Unlock the story hidden in data. Your digital investigation partner.

This script provides a set of tools for digital forensics and cybersecurity investigations, 
helping analysts extract insights from various data sources.

Author: Franck FERMAN (@franckferman), @branoodle, @MimiChan, @s4tb0y, @yametersa & @ectario
Created On: 11/03/2024
Version: 1.0.0
License: AGPL v3 (GNU Affero General Public License)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

from typing import List, Optional, Tuple

from pyfiglet import Figlet


def display_banner() -> None:
    """
    Display the script banner using the 'cybermedium' font.

    This function uses the Figlet library to render the banner text 'DataDetective'
    in a stylized format and prints it to the console.

    Raises:
        RuntimeError: If banner rendering fails.
    """
    try:
        banner = Figlet(font='cybermedium')
        print(banner.renderText('DataDetective'))
    except Exception as e:
        raise RuntimeError("Failed to render banner using Figlet: " + str(e))


def check_image_validity(image_path: str) -> Tuple[bool, str]:
    """
    Verify the validity of the specified disk image by checking if it has partitions.

    This function uses 'mmls' (from The Sleuth Kit) to determine whether the disk image
    contains valid partitions.

    Args:
        image_path (str): The file path to the disk image.

    Returns:
        Tuple[bool, str]: A tuple containing:
            - A boolean indicating whether the check was successful.
            - A descriptive message about the validation result.
    """
    try:
        output = subprocess.check_output(['mmls', image_path], stderr=subprocess.STDOUT, text=True)
        return True, "The specified image is valid and contains partitions.\n" + output
    except FileNotFoundError:
        return False, "Error: 'mmls' command not found. Please ensure The Sleuth Kit is installed."
    except subprocess.CalledProcessError as e:
        return False, f"Error validating image: {e.output.decode().strip()}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def list_partitions(image_path: str) -> Tuple[bool, str]:
    """
    List the partitions within the specified disk image, verifying its validity first.

    This function uses 'mmls' (from The Sleuth Kit) to display partition information.

    Args:
        image_path (str): The file path to the disk image.

    Returns:
        Tuple[bool, str]: A tuple containing:
            - A boolean indicating whether the listing was successful.
            - The output message containing partition details or an error message.
    """
    valid, message = check_image_validity(image_path)
    if not valid:
        return False, message

    try:
        output = subprocess.check_output(['mmls', image_path], stderr=subprocess.STDOUT, text=True)
        return True, f"Partitions detected:\n{output}"
    except FileNotFoundError:
        return False, "Error: 'mmls' command not found. Please ensure The Sleuth Kit is installed."
    except subprocess.CalledProcessError as e:
        return False, f"Failed to list partitions: {e.output.strip()}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def find_basic_data_partition_offset(image_path: str) -> Tuple[bool, int]:
    """
    Find the offset for the 'Basic data partition' within the specified disk image.

    This function parses the partition table output from 'mmls' (The Sleuth Kit)
    to locate the offset of the 'Basic data partition'.

    Args:
        image_path (str): The file path to the disk image.

    Returns:
        Tuple[bool, int]: A tuple containing:
            - A boolean indicating whether the offset was found.
            - The offset value (or 0 if not found).
    """
    success, output = list_partitions(image_path)
    if not success:
        return False, 0

    regex = re.compile(r'^\s*\d+:\s*\d+\s+(\d+)\s+\d+\s+\d+\s+.*\bBasic data partition\b', re.IGNORECASE)

    for line in output.splitlines():
        match = regex.search(line)
        if match:
            try:
                return True, int(match.group(1))
            except ValueError:
                return False, 0 

    return False, 0


def list_partition_files(image_path: str, offset: int, inode: str = "", recursive: bool = False) -> Tuple[bool, str]:
    """
    List the files within a partition or a specific directory in the partition, specified by its offset in the disk image.
    Optionally lists contents recursively.

    Args:
        image_path (str): The file path to the disk image.
        offset (int): The offset of the partition within the disk image.
        inode (str, optional): The inode of the directory to list its contents.
        recursive (bool, optional): Whether to list the contents recursively.

    Returns:
        Tuple[bool, str]: A tuple containing:
            - A boolean indicating whether the file listing was successful.
            - The output message or an error message.
    """
    command = ['fls', '-o', str(offset), image_path]

    if recursive:
        command.append('-r')

    if inode:
        command.append(inode)

    try:
        output = subprocess.run(command, text=True, check=True, capture_output=True)
        return True, output.stdout
    except FileNotFoundError:
        return False, "Error: The 'fls' command is not found. Ensure The Sleuth Kit (TSK) is installed."
    except subprocess.CalledProcessError as e:
        return False, f"Error listing files: {e.stderr.strip() if e.stderr else e}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def extract_specific_files(image_path: str, offset: int, output_dir: str) -> Tuple[bool, List[str]]:
    """
    Extract specific forensic artifacts like system/user registry hives, browser data, Windows logs, and MFT.

    Args:
        image_path (str): Path to the disk image.
        offset (int): Offset of the partition where files are extracted from.
        output_dir (str): Directory to store extracted files.

    Returns:
        Tuple[bool, List[str]]: A tuple with:
            - A boolean indicating success or failure.
            - A list of extracted file paths or error messages.
    """
    data_paths = {
        'system_registry': [r'Windows/System32/config/SYSTEM$'],
        'software_registry': [r'Windows/System32/config/SOFTWARE$'],
        'sam_registry': [r'Windows/System32/config/SAM$'],
        'security_registry': [r'Windows/System32/config/SECURITY$'],
        'user_profiles': [r'Users/.*/NTUSER\.DAT$'],
        'edge': [r'Users/.*/AppData/Local/Microsoft/Edge/User Data/Default/.*'],
        'ie': [r'Users/.*/AppData/Local/Microsoft/Internet Explorer/.*'],
        'firefox': [r'Users/.*/AppData/Roaming/Mozilla/Firefox/Profiles/.*'],
        'chrome': [r'Users/.*/AppData/Local/Google/Chrome/User Data/Default/.*'],
        'windows_security_logs': [r'Windows/System32/winevt/Logs/Security\.evtx'],
        'windows_system_logs': [r'Windows/System32/winevt/Logs/System\.evtx'],
        'mft': [r'\$MFT$']
    }

    extracted_files = []
    os.makedirs(output_dir, exist_ok=True)

    print("🔍 Starting forensic file extraction...")

    try:
        fls_output = subprocess.run(
            ['fls', '-p', '-r', '-o', str(offset), image_path],
            text=True, check=True, capture_output=True
        )

        inode_to_path = {}
        for line in fls_output.stdout.splitlines():
            parts = line.split(maxsplit=2)
            if len(parts) > 2 and ':' in parts[1]:
                inode = parts[1].split(':')[0]
                full_path = parts[2]
                inode_to_path[inode] = full_path

        for label, paths in data_paths.items():
            for path_regex in paths:
                pattern = re.compile(path_regex)

                for inode, full_path in inode_to_path.items():
                    if pattern.match(full_path):
                        sanitized_filename = full_path.replace('/', '_')
                        extracted_file_path = os.path.join(output_dir, f"{label}_{sanitized_filename}")

                        try:
                            with open(extracted_file_path, 'wb') as file:
                                subprocess.run(['icat', '-o', str(offset), image_path, inode], stdout=file, check=True)
                            extracted_files.append(extracted_file_path)
                        except subprocess.CalledProcessError:
                            print(f"❌ Failed to extract {full_path} (inode: {inode})")

        print("✅ Extraction completed.")
        return True, extracted_files

    except FileNotFoundError:
        return False, ["Error: The 'fls' or 'icat' command is missing. Ensure The Sleuth Kit (TSK) is installed."]
    except subprocess.CalledProcessError as e:
        return False, [f"Failed to process disk image: {e.stderr.strip() if e.stderr else e}"]
    except Exception as e:
        return False, [f"Unexpected error: {str(e)}"]


def extract_and_analyze_files(image_path: str, offset: int, output_dir: str) -> Tuple[bool, List[str]]:
    """
    Extract and analyze specific forensic files using external tools like RegRipper or Eric Zimmerman's tools.

    Args:
        image_path (str): Path to the disk image.
        offset (int): Offset of the partition to extract files from.
        output_dir (str): Directory to save extracted and analyzed data.

    Returns:
        Tuple[bool, List[str]]: 
            - A boolean indicating whether extraction and analysis were successful.
            - A list of analysis report paths or error messages.
    """
    results = []
    os.makedirs(output_dir, exist_ok=True)

    extraction_success, extracted_files = extract_specific_files(image_path, offset, output_dir)
    if not extraction_success:
        return False, ["Extraction failed!"]

    regripper_path = shutil.which('regripper')
    if not regripper_path:
        return False, ["Error: RegRipper not found. Ensure it is installed and in PATH."]

    print("🔍 Starting forensic analysis with RegRipper...")

    try:
        for file_path in extracted_files:
            filename = os.path.basename(file_path)
            
            if "system_registry" in filename:
                hive_type = "system"
            elif "software_registry" in filename:
                hive_type = "software"
            elif "sam_registry" in filename:
                hive_type = "sam"
            elif "security_registry" in filename:
                hive_type = "security"
            else:
                continue

            report_path = os.path.join(output_dir, f"{filename}_report.txt")
            
            with open(report_path, 'w') as report_file:
                subprocess.run(
                    ['perl', regripper_path, '-r', file_path, '-f', hive_type],
                    stdout=report_file, check=True
                )
            
            results.append(report_path)

        print("✅ Analysis completed.")
        return True, results

    except FileNotFoundError:
        return False, ["Error: RegRipper execution failed (not found)."]
    except subprocess.CalledProcessError as e:
        return False, [f"Error during forensic analysis: {e.stderr.strip() if e.stderr else e}"]
    except Exception as e:
        return False, [f"Unexpected error: {str(e)}"]


def show_files(image_path: str) -> Tuple[bool, str]:
    """
    Show files in the 'Basic data partition' of the disk image and return the success status and message.

    Args:
        image_path (str): The path to the disk image.

    Returns:
        Tuple[bool, str]: 
            - Boolean indicating success or failure.
            - A string message with results or an error description.
    """
    success, offset = find_basic_data_partition_offset(image_path)
    if not success:
        return False, "❌ Error: Could not locate 'Basic data partition'."

    success, message = list_partition_files(image_path, offset)
    if success:
        return True, f"✅ Files in 'Basic data partition':\n{message}"
    
    return False, f"❌ Error listing files: {message}"


def adjust_inode_output(inode_info: str) -> str:
    """
    Adjusts the inode output format to match the expected 'fls' command format.

    Args:
        inode_info (str): The inode string, typically in the format "X-Y-Z" or similar.

    Returns:
        str: A formatted inode string in the expected "X-Y-Z" format, 
             or the original input if it doesn't match the expected structure.
    """
    if not inode_info or not isinstance(inode_info, str):
        return inode_info

    parts = inode_info.split('-')
    
    return '-'.join(parts[:3]) if len(parts) >= 3 else inode_info


def find_inode_for_directory(directory_name: str, partition_contents: str) -> Tuple[bool, str]:
    """
    Finds the inode number of a specific directory within the partition contents.

    Args:
        directory_name (str): The name of the directory to locate.
        partition_contents (str): The output of `list_partition_files` for the root of the partition.

    Returns:
        Tuple[bool, str]: 
            - (True, inode) if the directory is found.
            - (False, "Directory not found.") if no match is found.
    """
    if not directory_name or not isinstance(directory_name, str):
        return False, "Invalid directory name."

    if not partition_contents or not isinstance(partition_contents, str):
        return False, "Invalid partition contents."

    regex = re.compile(r'd/d (\d+-\d+-\d+):\s+{}\b'.format(re.escape(directory_name)))

    for line in partition_contents.splitlines():
        match = regex.match(line)
        if match:
            return True, adjust_inode_output(match.group(1))

    return False, "Directory not found."


def resolve_directory_path(image_path: str, offset: int, directory_path: str) -> Tuple[bool, str, str]:
    """
    Resolve a directory path to its final inode within the 'Basic data partition' of the disk image.

    Args:
        image_path (str): The path to the disk image.
        offset (int): The offset of the 'Basic data partition'.
        directory_path (str): The directory path to resolve.

    Returns:
        Tuple[bool, str, str]: 
            - (True, inode, "Success") if the directory is found.
            - (False, "", "Error message") if the resolution fails.
    """
    # Vérification des entrées
    if not image_path or not isinstance(image_path, str):
        return False, "", "Invalid image path."

    if not isinstance(offset, int) or offset < 0:
        return False, "", "Invalid offset value."

    if not directory_path or not isinstance(directory_path, str):
        return False, "", "Invalid directory path."

    # Normalisation du chemin et séparation en composants
    directory_components = directory_path.strip().replace('\\', '/').split('/')
    current_inode = ""  # Inode courant, vide pour commencer à la racine

    for directory_name in directory_components:
        if not directory_name:  # Ignore les entrées vides (ex: double slash)
            continue

        # Liste les fichiers du répertoire actuel
        success, partition_contents = list_partition_files(image_path, offset, inode=current_inode, recursive=False)
        if not success:
            return False, "", f"Failed to list directory contents for inode '{current_inode}'"

        # Recherche l'inode du répertoire actuel
        success, inode = find_inode_for_directory(directory_name, partition_contents)
        if not success:
            return False, "", f"Directory '{directory_name}' not found in path '{directory_path}'"

        # Mise à jour de l'inode pour descendre dans l'arborescence
        current_inode = inode

    return True, current_inode, "Directory path resolved successfully."


def show_dir(image_path: str, directory_path: str, recursive: bool = False) -> Tuple[bool, str]:
    """
    Show the contents of a specific directory or a path within the 'Basic data partition' of the disk image, optionally recursively.

    Args:
        image_path (str): The path to the disk image.
        directory_path (str): The directory path to show its contents.
        recursive (bool): Whether to list the contents recursively.

    Returns:
        Tuple[bool, str]: 
            - (True, directory_contents) if the directory is found.
            - (False, "Error message") if the operation fails.
    """
    if not image_path or not isinstance(image_path, str):
        return False, "Invalid image path."

    if not directory_path or not isinstance(directory_path, str):
        return False, "Invalid directory path."

    success, offset = find_basic_data_partition_offset(image_path)
    if not success:
        return False, "Failed to locate the 'Basic data partition'."

    if '/' in directory_path or '\\' in directory_path:
        success, final_inode, message = resolve_directory_path(image_path, offset, directory_path)
    else:
        success, root_contents = list_partition_files(image_path, offset)
        if not success:
            return False, "Failed to list root directory contents."

        success, final_inode = find_inode_for_directory(directory_path, root_contents)
        message = f"Directory '{directory_path}' not found in root." if not success else ""

    if not success:
        return False, message

    success, directory_contents = list_partition_files(image_path, offset, inode=final_inode, recursive=recursive)
    if not success:
        return False, "Failed to list directory contents."

    return True, directory_contents


def validate_args(args: argparse.Namespace) -> None:
    """
    Validate argument combinations to prevent conflicts or missing values.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Raises:
        SystemExit: If conflicting or missing arguments are detected.
    """
    if args.check_image and args.show_partitions:
        print("Error: --check-image and --show-partitions cannot be used together.", file=sys.stderr)
        sys.exit(1)

    if args.extract_data and not args.output_dir:
        print("Error: --extract-data requires --output-dir to specify the extraction directory.", file=sys.stderr)
        sys.exit(1)


def execute_action(args: argparse.Namespace) -> None:
    """
    Execute the appropriate action based on the provided arguments.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Raises:
        SystemExit: Exits with code 0 for success or 1 for failure.
    """
    success, message = False, "No valid action executed."

    if args.check_image:
        success, message = check_image_validity(args.image)
    elif args.show_partitions:
        success, message = list_partitions(args.image)
    elif args.show_files:
        success, message = show_files(args.image)
    elif args.show_dir:
        success, message = show_dir(args.image, args.show_dir, args.recursive)
    elif args.extract_data:
        success, offset = find_basic_data_partition_offset(args.image)
        if not success:
            print("Failed to find 'Basic data partition'.", file=sys.stderr)
            sys.exit(1)
        success, message = extract_and_analyze_files(args.image, offset, args.output_dir)
    else:
        success, message = check_image_validity(args.image)

    print(message)
    sys.exit(0 if success else 1)


def main() -> None:
    """
    Main function to process command-line arguments and execute actions.

    Parses CLI arguments, validates them, displays a banner, and executes the corresponding action.

    Raises:
        SystemExit: If invalid argument combinations are detected or if execution fails.
    """
    parser = argparse.ArgumentParser(
        description="Unlock the story hidden in data - Your digital investigation partner."
    )
    
    # Required argument
    parser.add_argument(
        "-i", "--image", required=True, 
        help="Path to the disk image file."
    )
    
    # Validation & Analysis Options
    parser.add_argument(
        "--check-image", action="store_true", 
        help="Check if the disk image is valid and contains partitions."
    )
    parser.add_argument(
        "--show-partitions", action="store_true", 
        help="Show partitions in the disk image without further analysis."
    )
    
    # File & Directory Listing Options
    parser.add_argument(
        "--show-files", action="store_true", 
        help="Show files in the 'Basic data partition' of the disk image."
    )
    parser.add_argument(
        "--show-dir", metavar="DIRECTORY", 
        help="Specify a directory to list its contents from the 'Basic data partition'."
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true", 
        help="Use with --show-dir to list directory contents recursively."
    )

    # Data Extraction Options
    parser.add_argument(
        "-e", "--extract-data", metavar="DATA_TYPE", 
        help="Extract important files for investigation."
    )
    parser.add_argument(
        "-o", "--output-dir", metavar="DIRECTORY", 
        help="Output directory for extracted files."
    )

    args = parser.parse_args()

    validate_args(args)
    display_banner()
    execute_action(args)


if __name__ == "__main__":
    main()
