# apt install gdb-multiarch
# docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# docker build -t cli_minimal_aarch64 .
# To run:
#   * tty$: python solution.py [DEBUG] [NOASLR] [GDB] [REMOTE]
# Or manually invoke the container:
#   * docker run --rm -it -p 12345:12345 -p 7778:7778 cli_minimal_aarch64 /pwn/cli

FROM arm64v8/ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive 

# Install generally necessary packages
RUN apt update && apt install gcc git socat curl file ltrace strace -yy

# Fix locale
# For Debian or Ubuntu, you also need to install "locales" to have `locale-gen` available
RUN apt install locales -yy
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     

# Install debugging ARM binaries
RUN apt install gdbserver qemu-user qemu-user-static -yy

# Perform remaining actions to setup the target binary
RUN mkdir /pwn

# [Optionally] copy source and compile
# COPY cli.c /pwn/cli.c
# RUN gcc -D_FORTIFY_SOURCE=2 -fno-stack-protector -zexecstack -o /pwn/cli /pwn/cli.c

COPY cli /pwn/cli
COPY flag.txt /pwn/flag.txt
COPY run.sh /pwn/run.sh

RUN groupadd ctf && \
    useradd -G ctf --home=/pwn pwn

RUN chmod 700 /pwn/cli
RUN chmod 700 /pwn/run.sh

# socat and gdb ports. See run.sh
EXPOSE 7778 12345

ENV DEBIAN_FRONTEND=dialog
ENTRYPOINT ["/pwn/run.sh"]
# CMD "/bin/bash"
