import docker
import logging
import tarfile
import os
import io

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s')

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

    def move_file_to_container(self, container: docker.models.containers.Container, src_path:str, dest_path:str, op:str='file'):
        """
        Move a file from the host to the Docker container.
        Args:
            container (docker.models.containers.Container): The Docker container to move the file into.
            src_path (str): Path to the source file on the host.
            dest_path (str): Destination path inside the Docker container.
        """

        match op:
            case 'analyze':
                arcname = 'filesToAnalyze'
            case 'rules':
                arcname = 'rules'
            case _:
                arcname = ''

        try:
            tar_data = make_tarfile(src_path, arcname)
            container.put_archive(dest_path, tar_data)
            container.exec_run(f"tar -xvf {dest_path}/{arcname} -C {dest_path}")
            logging.info(f"File moved successfully to {container.name}.")
        except Exception as e:
            logging.error(f"Failed to move file to container {container.name}: {e}")

    def run_container(self, image_name:str, container_name:str, files_to_analyze_path:str):
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
                self.start_container(image_name, container, files_to_analyze_path)
            except docker.errors.NotFound:
                logging.info(f"Container '{container_name}' not found. Creating a new one and starting it.")
                container = self.docker_client.containers.run(image_name, name=container_name, detach=True, command="tail -f /dev/null") # TODO: Check if this is correct of if I should add a ENTRYPOINT in the Dockerfile
                logging.info(f"New container '{container_name}' started with ID: {container.id}")

                self.start_container(image_name, container, files_to_analyze_path)
                #self.move_file_to_container(container, 'docker/yara/run-rules.py', '/rules/rules.py')
                #self.move_file_to_container(container, 'docker/yara/raw/yara-rules-full.yar', '/rules/yara-rules-full.yar')
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

    def start_container(self, image_name:str, container: docker.models.containers.Container, files_to_analyze_path:str):
        """
        Start a Docker container with the specified image.
        Args:
            image_name (str): Name of the Docker image to run.
        """
        try:
            self.containers.append(container)

            # Move files to analyze to container.
            self.move_file_to_container(container, f'files/{files_to_analyze_path}', f'/rules/')

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