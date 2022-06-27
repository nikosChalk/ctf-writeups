# apt install gdb-multiarch
# docker build -t cli_minimal_native .
# To run:
#   * tty$: python solution.py [DEBUG] [NOASLR] [GDB] [REMOTE]
# Or manually invoke the container:
#   * docker run --rm -it -p 12345:12345 -p 7778:7778 cli_minimal_native /pwn/cli

FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive 

# Install generally necessary packages
RUN apt update && apt install python3 python3-pip git gcc cmake build-essential \
    socat htop tmux curl wget file locales \
    ltrace strace vim -yy

# Fix locale
# For Debian or Ubuntu, you also need to install "locales" to have `locale-gen` available
RUN apt install locales -yy
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     

# Install packages for running ARM binaries
RUN apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu binutils-aarch64-linux-gnu-dbg -yy
RUN apt install gdbserver qemu-user qemu-user-static -yy

# Install python packages
RUN pip3 install wheel ipython

# Perform remaining actions to setup the target binary
RUN mkdir /pwn

# [Optionally] copy source and compile
# COPY cli.c /pwn/cli.c
# RUN aarch64-linux-gnu-gcc -D_FORTIFY_SOURCE=2 -fno-stack-protector -zexecstack -o /pwn/cli /pwn/cli.c

COPY cli /pwn/cli
COPY run.sh /pwn/run.sh
COPY flag.txt /pwn/flag.txt

RUN groupadd ctf && \
    useradd -G ctf --home=/pwn pwn

RUN chmod 700 /pwn/cli
RUN chmod 700 /pwn/run.sh

# socat and gdb ports. See run.sh
EXPOSE 7778 12345

ENV DEBIAN_FRONTEND=dialog
ENTRYPOINT ["/pwn/run.sh"]
# CMD "/bin/bash"
