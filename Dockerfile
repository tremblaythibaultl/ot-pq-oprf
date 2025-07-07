FROM ubuntu:24.04

RUN apt-get update && apt-get upgrade -y && apt-get install -y build-essential git make g++ cmake libtool python3 libboost-all-dev libssl-dev libgmp-dev vim

WORKDIR /home/
RUN git clone https://github.com/osu-crypto/libOTe  
WORKDIR /home/libOTe
RUN git checkout e05696d 

RUN python3 build.py -DENABLE_MR_KYBER=ON -DENABLE_IKNP=ON -DENABLE_SOFTSPOKEN_OT=ON -DENABLE_SILENTOT=ON -DLIBOTE_STD_VER=20 -DENABLE_MOCK_OT=OFF -DENABLE_KKRT=ON --boost --sodium --install

# run install again to copy sodium files that weren't copied before.
RUN python3 build.py --install

WORKDIR /home/
RUN mkdir ot-pq-oprf && mkdir ot-pq-oprf/build
COPY ./main.cpp ot-pq-oprf/main.cpp
COPY CMakeLists.txt ot-pq-oprf/CMakeLists.txt

WORKDIR /home/ot-pq-oprf/build

RUN cmake .. && make

SHELL ["/bin/bash", "-c"]
