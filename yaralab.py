import argparse
import os
import logging
import atexit

from time import sleep
from docker_handler import Docker_Handler
from docker_db_handler import MongoDB_Handler

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')

_docker_handler_instance = None

def get_docker_handler():
    """
    Get or create the singleton Docker_Handler instance.
    Returns:
        Docker_Handler: The singleton Docker_Handler instance.
    """
    global _docker_handler_instance
    if _docker_handler_instance is None:
        _docker_handler_instance = Docker_Handler()
        logging.info("Created new Docker_Handler instance")
    return _docker_handler_instance

def stop_containers():
    """
    Cleanup function to stop all Docker containers from the compose file.
    This function is registered to run on exit.
    """
    global _docker_handler_instance
    if _docker_handler_instance is not None and Docker_Handler._compose_started:
        logging.info("Cleaning up all Docker Compose containers...")
        try:
            _docker_handler_instance.stop_containers()
        except Exception as e:
            logging.error(f"Error stopping Docker Compose containers: {e}")
    else:
        logging.info("No Docker Compose services to clean up.")

atexit.register(stop_containers)

def parse_args():
    """
    Parse command line arguments for PYFA tool.
    Returns:
        argparse.Namespace: Parsed command line arguments.
    """

    parser = argparse.ArgumentParser(description="PYFA: A tool for YARA rule management and analysis.")
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
        '-gt', '--group-by-tags',
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
        help='Group output by tags instead of rules.'
    )

    parser.add_argument(
        '-dn', '--dName',
        type=str,
        required=False,
        default="yara_container",
        help='Name for the container. Defaulted to "yara_container"'
    )

    parser.add_argument(
        '-db', '--dataBase',
        default=False,
        required=False,
        action=argparse.BooleanOptionalAction,
        help='Enable database integration for rule management. Follow with -ldb to load rules into the database or -t to filter rules by tags.'
    )

    parser.add_argument(
        '-ldb', '--loadDb',
        dest='load_db',
        type=str,
        required=False,
        help='Load rules into the database from the specified YARA file. Provide the path to the file i.e. "./rules/my_rules.yar"'
    )

    parser.add_argument(
        '-t', '--tags',
        type=str,
        nargs='*',
        required=False,
        default=None,
        help='Tags to filter rules from database. Can specify none (all rules), one tag, or multiple tags.'
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
    Uses the singleton Docker_Handler instance.
    """
    create_directories()

    docker_handler = get_docker_handler()
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

    docker_handler = get_docker_handler()
    docker_handler.run_container(
        image_name="yara",
        container_name=args.dName,
    )

    if args.dataBase:
        mdb = MongoDB_Handler()
        if args.load_db:
            mdb.load_rules_from_file(args.load_db)

        docker_handler.run_cmd(
            container_name=args.dName,
            cmd=f"python3 /data/run-rules.py -f {args.input} {'-gt' if args.group_by_tags else ''} -db"
        )
        
    else: 

        docker_handler.run_cmd(
            container_name=args.dName,
            cmd=f"python3 /data/run-rules.py -f {args.input} {'-gt' if args.group_by_tags else ''}"
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