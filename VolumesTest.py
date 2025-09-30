import docker
import os

# Docker image and volume settings
IMAGE_NAME = "alpine:latest"
CONTAINER_NAME = "volume_test_container"
VOLUME_HOST_PATH = os.path.abspath("./tmp/host_data")
VOLUME_CONTAINER_PATH = "/data"

client = docker.from_env()

# Create the volume mapping
volumes = {
    VOLUME_HOST_PATH: {
        'bind': VOLUME_CONTAINER_PATH,
        'mode': 'rw'
    }
}

# Pull the image if not present
client.images.pull(IMAGE_NAME)

# Run the container with the volume attached
container = client.containers.run(
    IMAGE_NAME,
    name=CONTAINER_NAME,
    command="sleep 1200",
    volumes=volumes,
    detach=True
)

print(f"Container '{CONTAINER_NAME}' started with volume {VOLUME_HOST_PATH} mounted to {VOLUME_CONTAINER_PATH}.")

# Cleanup: stop and remove the container after use (optional)
# container.stop()
# container.remove()