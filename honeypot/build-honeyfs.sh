#!/bin/bash

IMAGE_NAME="cowrie_fs_image"
CONTAINER_NAME="cowrie_fs_container"
COWRIE_DIR="/etc/cowrie" # Where Cowrie is installed in the container
HONEYFS_DIR="real_honeyfs" # Where the full filesystem should be stored

set -e
trap "docker stop $CONTAINER_NAME; docker rm $CONTAINER_NAME; echo 'Container $CONTAINER_NAME has been stopped and removed.'" EXIT

# Build and run the container
docker build -t $IMAGE_NAME -f Dockerfile.honeyfs .
docker run -d --name $CONTAINER_NAME $IMAGE_NAME

# Inside the container, run the createfs command to generate the Pickle file
docker exec $CONTAINER_NAME /bin/bash -c "source $COWRIE_DIR/cowrie-env/bin/activate && $COWRIE_DIR/bin/createfs -l / -o $COWRIE_DIR/custom.pickle"

# Copy the Pickle file from the container
docker cp $CONTAINER_NAME:$COWRIE_DIR/custom.pickle ./fs.pickle

# Copy the entire filesystem into honeyfs
docker cp $CONTAINER_NAME:/ $HONEYFS_DIR

# Make it so you can't view the contents of the $COWRIE_DIR from inside the honeypot
rm -rf $HONEYFS_DIR$COWRIE_DIR

echo "Done"
