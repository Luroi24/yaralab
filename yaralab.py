import argparse
import os
import logging
from docker_handler import DockerHandler

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')

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
        required=True,
        help='Path to the output file where results will be saved.'
    )
    parser.add_argument(
        '-l', '--label',
        type=str,
        required=False,
        help='Label for the yara rules to be processed. If not provided, all rules will be processed.'
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


if __name__ == "__main__":
    args = parse_args()
    create_directories()

    docker_handler = DockerHandler()
    
    logging.info(f"Input file: {args.input}")
    logging.info(f"Output file: {args.output}")