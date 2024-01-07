# docker build -t trustmee .
#
# docker run -v ./solution:/home/ctf/solution --cap-add=SYS_PTRACE --rm -it --name trustmee_1 trustmee
#  * --cap-add=SYS_PTRACE is used so that we can run gdb inside
#  * mounting a volume for easier exploit development
# To pwn the challenge:
#   docker exec -it -u ctf trustmee_1 /bin/bash
# To debug the challenge
#   docker exec -it -u root trustmee_1 /bin/bash
FROM ubuntu:22.04@sha256:b492494d8e0113c4ad3fe4528a4b5ff89faa5331f7d52c5c138196f69ce176a6

# Fix locales
ENV LANG en_US.utf8
RUN apt-get update && apt-get install -y locales
RUN localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

# Dependencies
RUN apt-get install -y gdb
RUN apt-get update && \
    apt-get install -y wget xinetd cmake build-essential unzip git dropbear rsync openssh-client libcap2-bin python3 python3-pip && apt-get clean

RUN useradd -d /home/ctf/ -m -s /bin/bash ctf && passwd -d ctf

WORKDIR /home/ctf

# Setup pwndbg
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /home/ctf/pwndbg
RUN ./setup.sh
WORKDIR /home/ctf/

# Clone and install OpenTEE
RUN apt-get install -y build-essential git pkg-config uuid-dev libelf-dev wget curl autoconf automake libtool libfuse-dev

RUN mkdir -p /home/ctf/bin
RUN curl http://commondatastorage.googleapis.com/git-repo-downloads/repo > /home/ctf/bin/repo
RUN chmod +x /home/ctf/bin/repo
# x.x
RUN  ln -s /usr/bin/python3 /usr/bin/python 
RUN wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v3.1.0.tar.gz
RUN tar -xf v3.1.0.tar.gz && cd mbedtls-3.1.0
WORKDIR /home/ctf/mbedtls-3.1.0
RUN cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
RUN make -j && make install

WORKDIR /home/ctf
RUN mkdir opentee 
WORKDIR /home/ctf/opentee
RUN /home/ctf/bin/repo init -u https://github.com/Open-TEE/manifest.git
RUN /home/ctf/bin/repo sync -j10

RUN mkdir build
RUN sed -i 's| #!/bin/sh -e|#!/bin/bash|' autogen.sh
RUN cat autogen.sh
WORKDIR /home/ctf/opentee/build
RUN ../autogen.sh
RUN make -j && make install

# Configure the installation
WORKDIR /home/ctf/
RUN rm -r /opt/OpenTee/lib/TAs 
RUN mkdir /opt/OpenTee/lib/TAs
COPY grade_ta.so /opt/OpenTee/lib/TAs/
RUN chmod +x /opt/OpenTee/lib/TAs/grade_ta.so
COPY opentee.conf /etc/
RUN ln -s /usr/local/lib/libmbedcrypto.so.3.1.0 /opt/OpenTee/lib/libmbedcrypto.so.11

ENV OPEN_TEE_PATH /opt/OpenTee
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:$OPEN_TEE_PATH/lib"

# Copy flag
COPY flag.txt /opt/OpenTee/
RUN chmod 000 /opt/OpenTee/flag.txt

#RUN mkdir /app
COPY run.sh /
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]