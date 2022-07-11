FROM ubuntu:22.04
RUN apt-get update && apt-get install python3 python3-pip -yy
RUN pip install ipython

COPY treebox.py /home/treebox.py
COPY flag       /home/flag

WORKDIR /home
CMD "/bin/bash"
