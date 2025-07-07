## Build
This repository contains a [Dockerfile](Dockerfile) that fetches and builds all dependencies required by [`main.cpp`](main.cpp), which contains both the code for the preprocessing and the OPRF online phase.

### Requirements
Linux/amd64 with AVX2 available. 
**MacOS/arm64 and other platforms are not supported.**
Docker is also required - we recommend installing docker according to the guide provided [here](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).

### Instructions
To build the Docker image, make sure you have Docker properly installed and run 
```bash
$ docker build -t oprf .
```
Depending on your Docker installation, you may have to prepend the `docker` commands with `sudo`. 

This will fetch and build [libOTe](https://github.com/osu-crypto/libOTe) with the appropriate options. 
Once the image is done building, you can run a container with this image by running
```bash
$ docker run -it oprf
```
This will spawn a container and a `bash` instance. From there, you can execute 
```bash
./oprf
```
Parameters can be adjusted via the constants in the `/home/ot-pq-oprf/main.cpp` file. Rebuilding is necessary and can be achieved by executing `make` in the `/home/ot-pq-oprf/build` directory inside the container.

### Performance discrepancies
The measures provided in the paper were obtained from a native build on ubuntu 24.04 running on an AWS EC2 instance with 4 vCPUs and 16 GB memory. 
Building natively or with Docker on different machines may yield different measures.
To reproduce the measures from the paper, one may follow the Dockerfile steps to natively install libOTe which will allow to natively build the Pool OPRF implementation. 