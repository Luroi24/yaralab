# Example: py yaralab.py -i pings/pingsToGoogle-upx
# Hay que colocar el nombre relativo (respecto a la carpeta de files)
import docker
import logging
import tarfile
import os
import io
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')
VOLUME_HOST_PATH = os.path.abspath("./remote")
VOLUME_CONTAINER_PATH = "/data"

def make_tarfile(src_path, arcname):
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
        tar.add(src_path, arcname=arcname)
    tar_stream.seek(0)
    return tar_stream


class Docker_Handler:
    """
    A class to handle Docker operations for YaraLab.
    This class can be expanded with methods to build, run, and manage Docker containers.
    """

    containers = []

    def __init__(self):
        logging.info("Docker_Handler initialized. Ready to manage Docker operations.")
        self.docker_client = docker.from_env()

    def run_container(self, image_name:str, container_name:str):
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

        finally:
            try:
                container = self.docker_client.containers.get(container_name)
                container.start()
                logging.info(f"Found existing container '{container_name}'. Starting it.")
                self.start_container(image_name, container)
            except docker.errors.NotFound:
                logging.info(f"Container '{container_name}' not found. Creating a new one and starting it.")
                
                container = self.docker_client.containers.run(
                    image_name,
                    volumes={
                        VOLUME_HOST_PATH: {
                            'bind': VOLUME_CONTAINER_PATH,
                            'mode': 'rw'
                        }
                    },
                    name=container_name,
                    detach=True, command="tail -f /dev/null"
                ) 
                # TODO: Check if this is correct of if I should add a ENTRYPOINT in the Dockerfile

                # Script to run yara
                logging.info(f"New container '{container_name}' started with ID: {container.id}")

                self.start_container(image_name, container)
            except Exception as e:
                logging.error(f"Failed to start or create container '{container_name}': {e}")

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

    def start_container(self, image_name:str, container: docker.models.containers.Container):
        """
        Start a Docker container with the specified image.
        Args:
            image_name (str): Name of the Docker image to run.
        """
        try:
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

    def get_file_from_container(self, file_path: str, output_path: str, container_name: str):
        """
        Get a file from the specified Docker container.
        Args:
            file_path (str): Path to the file inside the Docker container.
            output_path (str): Path to save the file content on the host.
            container_name (str): Name of the Docker container to get the file from.
        """
        logging.info(f"Getting file '{file_path}' from Docker container '{container_name}'.")
        try:
            container = self.docker_client.containers.get(container_name)
            bits, stat = container.get_archive(file_path)
            logging.info(f"Stat info: {stat}")

            tar_bytes = b''.join(bits)
            if not tar_bytes:
                logging.error(f"No data received from container for file '{file_path}'.")
                return None

            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        # Extract file to a temporary location
                        temp_dir = os.path.dirname(output_path)
                        temp_file_path = os.path.join(temp_dir, member.name)
                        tar.extract(member, path=temp_dir)
                        # Move/rename the extracted file to output_path
                        timestamp = time.strftime("%Y%m%d%H%M%S")
                        new_file = os.path.join(os.path.dirname(output_path), f"{timestamp}_{member.name}")
                        os.rename(temp_file_path, new_file)
                        logging.info(f"Extracted file saved to {output_path}")
                        return output_path
                logging.error(f"No file found in tar archive from container for file '{file_path}'.")
                return None
        except docker.errors.NotFound:
            logging.error(f"Container '{container_name}' not found.")
        except Exception as e:
            logging.error(f"Failed to get file from Docker container '{container_name}': {e}")

    def run_cmd(self, container_name:str, cmd:str):
        """
        Run a command in the specified Docker container.
        Args:
            container_name (str): Name of the Docker container to run the command in.
            cmd (str): Command to execute in the Docker container.
        """
        logging.info(f"Running command '{cmd}' in Docker container '{container_name}'.")
        try:
            container = self.docker_client.containers.get(container_name)
            exec_result = container.exec_run(cmd)
            logging.info(f"Command executed successfully: {exec_result.output.decode()}")
            return exec_result.output.decode()
        except docker.errors.NotFound:
            logging.error(f"Container '{container_name}' not found.")
        except Exception as e:
            logging.error(f"Failed to run command in Docker container '{container_name}': {e}")