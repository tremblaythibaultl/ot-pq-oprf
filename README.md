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

This will fetch and build [libOTe](https://github.com/osu-crypto/libOTe) with the appropriate build options. 
Once the image is done building, you can run a container with this image by running
```bash
$ docker run -it oprf
```
This will launch a container and a `bash` instance. From there, you can execute 
```bash
$ ./oprf
```
Parameters can be adjusted via the constants in the `/home/ot-pq-oprf/main.cpp` file. Rebuilding is necessary and can be achieved by executing `make` in the `/home/ot-pq-oprf/build` directory inside the container.

### Performance discrepancies
The measures provided in the paper were obtained from a native build on ubuntu 24.04 running on an AWS EC2 instance with 4 vCPUs and 16 GB memory. 
Building natively or with Docker on different machines may yield different measures.
To reproduce the measures from the paper, one may follow the Dockerfile steps to natively install libOTe which will allow to natively build the Pool OPRF implementation. 

## Code structure
All the code relevant to the experiments is included in the [main.cpp](main.cpp) file. 
Comments throughout the file detail how the code is structured. 

At a high level, the code contains several implementations of the client and server roles for each phase of the preprocessing step as described in Figure 3. 
Each implementation uses a different OT extender, provided by the [libOTe](https://github.com/osu-crypto/libOTe) library.
The `benchmark_alt_preproc` function launches an execution of each of the three variants of preprocessing (`IKNP`, `Silent OT (n)` and `Silent OT (n * kappa)`) in order to obtain the measures presented in Tables 2, 4 and 6. 

The `main` function provides a working example of the online phase of the OPRF. It follows the description given in Figure 4, and its results are used to fill in Tables 3 and 5.

In order to entirely reproduce the results presented in the tables, one must launch the executable several times to obtain an average and repeat the process for each parameter set. 
Client and server complexity are respectively measured as described in the text output of the executable and in the code.

## Parameters
As is, the file contains a set of paramaters of interest for comparison with prior work (c.f. Table 4). 
Alternative parameter sets presented in the paper can be benchmarked by e.g. setting
```c
const uint n = 415;
const uint tau = 1 << 18;
const uint lg_q = 8;
const uint lg_lg_p = 2;

const uint kappa = 16384;
```
in the `main.cpp` file for the `(n, q, p) = (415, 2^8, 2^4)` parameter set.

The executable must then be rebuilt from the `build` directory by running the following commands: 
```bash
$ cd build
$ make
$ ./oprf
```