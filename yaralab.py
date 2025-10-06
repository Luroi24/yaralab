import argparse
import os
import logging
import atexit

from time import sleep
from docker_handler import Docker_Handler

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')

def stop_containers():
    """
    Cleanup function to stop Docker containers.
    This function is registered to run on exit.
    """
    logging.info(f"Cleaning up Docker containers... {Docker_Handler.containers}")
    for container in Docker_Handler.containers:
        try:
            container.stop()
            logging.info(f"Stopped container: {container.name}")
        except Exception as e:
            logging.error(f"Error stopping/removing container {container.name}: {e}")

atexit.register(stop_containers)

def parse_args():
    """
    Parse command line arguments for YaraLab tool.
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """

    parser = argparse.ArgumentParser(description="YaraLab: A tool for YARA rule management and analysis.")
    parser.add_argument(
        '-i', '--input',
        type=str,
        required=True,
        help='Path to the input file containing YARA rules or signatures.'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default="outputs",
        help='Path to the output file where results will be saved.'
    )
    parser.add_argument(
        '-l', '--label',
        type=str,
        required=False,
        help='Label for the yara rules to be processed. If not provided, all rules will be processed.'
    )
    parser.add_argument(
        '-dn', '--dName',
        type=str,
        required=False,
        default="yara_container",
        help='Name for the container. Defaulted to "yara_container"'
    )

    return parser.parse_args()

def create_directories():
    """
    Create necessary directories for the YaraLab tool.
    This function can be expanded to create specific directories as needed.
    """
    
    directories = ['outputs']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Created directory: {directory}")

def get_name_from_path(file_path: str) -> str:
    """
    Extract the file name from a given file path.
    Args:
        file_path (str): The full path to the file.
    Returns:
        str: The extracted file name.
    """

    if os.path.isdir(file_path):
        return os.path.basename(os.path.normpath(file_path))
    elif os.path.isfile(file_path):
        return os.path.basename(file_path)
    
def simple_test(run_string: str = "", output:str="outputs", dName: str = "yara_container"):
    """
    Simple test function to demonstrate Docker container management.
    This function creates a Docker container, runs a command, and retrieves a file.
    """
    create_directories()

    docker_handler = Docker_Handler()
    docker_handler.run_container(
        image_name="yara",
        container_name=dName,
    )

    docker_handler.run_cmd(
        container_name=dName,
        cmd=run_string
    )

    docker_handler.get_file_from_container(
        file_path="/rules/output/results.json",
        output_path=f"{output}/results.json",
        container_name=dName
    )

    docker_handler.run_cmd(
        container_name=dName,
        cmd=f"rm -rf /rules/output"
    )

if __name__ == "__main__":
    args = parse_args()
    create_directories()

    docker_handler = Docker_Handler()
    docker_handler.run_container(
        image_name="yara",
        container_name=args.dName,
    )

    docker_handler.run_cmd(
        container_name=args.dName,
        cmd=f"python3 /data/run-rules.py -f {args.input} -gt"
    )

    docker_handler.get_file_from_container(
        file_path="/rules/output/results.json",
        output_path=f"{args.output}/results.json",
        container_name=args.dName
    )

    docker_handler.run_cmd(
        container_name=args.dName,
        cmd=f"rm -rf /rules/output"
    )

    logging.info(f"Input file: {args.input}")
    logging.info(f"Output file: {args.output}")

    # Pause here
    #sleep(1000)