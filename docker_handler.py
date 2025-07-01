import docker
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')

class Docker_Handler:
    """
    A class to handle Docker operations for YaraLab.
    This class can be expanded with methods to build, run, and manage Docker containers.
    """
    def __init__(self):
        logging.info("Docker_Handler initialized. Ready to manage Docker operations.")
        self.docker_client = docker.from_env()
        self.containers = []

    def run_container(self, image_name:str):
        """
        Run a Docker container with the specified image and command.
        Args:
            image_name (str): Name of the Docker image to run.
            command (str): Command to execute in the Docker container.
        """

        logging.info(f"Running Docker container with image: {image_name}.")
        try:
            self.docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            logging.error(f"Docker image '{image_name}' not found. Starting build process.")
            try:
                self.build_image(image_name, "latest")
            except Exception as e:
                logging.error(f"Failed to build Docker image '{image_name}': {e}")
        except Exception as e:
            logging.error(f"Error accessing Docker image '{image_name}': {e}")

    def build_image(self, image_name:str, tag:str):
        """
        Build a Docker image.
        Args:
            image_name (str): Name of the Docker image to build.
        """
        logging.info(f"Building Docker image: {image_name}")
        try:
            self.docker_client.images.build(path=f'.images/{image_name}', tag=tag)
            logging.info(f"Docker image '{image_name}' built successfully.")
        except docker.errors.BuildError as e:
            logging.error(f"Failed to build Docker image '{image_name}': {e}")

    def start_container(self, image_name:str):
        """
        Start a Docker container with the specified image.
        Args:
            image_name (str): Name of the Docker image to run.
        """
        logging.info(f"Starting Docker container with image: {image_name}")
        try:
            container = self.docker_client.containers.run(image_name, detach=True)
            self.containers.append(container)
            logging.info(f"Docker container started with ID: {container.id}")
            return container.id
        except docker.errors.ContainerError as e:
            logging.error(f"Failed to start Docker container with image '{image_name}': {e}")

    def stop_containers(self):
        """
        Stop all running Docker containers managed by this handler.
        """
        logging.info("Stopping all running Docker containers.")
        for container in self.containers:
            try:
                container.stop()
                logging.info(f"Stopped Docker container with ID: {container.id}")
            except docker.errors.APIError as e:
                logging.error(f"Failed to stop Docker container with ID '{container.id}': {e}")