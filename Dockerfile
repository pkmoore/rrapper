FROM ubuntu

########################
# Initialization
########################

# get necessary dependencies and cleanup
RUN apt-get -q update
RUN apt-get -q -y install \
      ccache cmake make g++-multilib gdb libdw-dev \
      pkg-config coreutils python-pexpect manpages-dev git \
      ninja-build capnproto libcapnp-dev autoconf \
      libpython2.7-dev zlib1g-dev python-pip
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# get necessary CrashSimulator repos
RUN git clone -b spin-off https://github.com/pkmoore/rr
RUN git clone https://github.com/pkmoore/rrapper

# create a new nonroot user
RUN useradd crashsim -m

########################
# Installing modified rr
########################

WORKDIR rr/

# compile and install the modified strace
RUN cd third-party/strace && ./bootstrap && autoreconf && \
    ./configure && make && make install

# compile and install rr
RUN mkdir obj && cd obj && cmake .. && make -j8 && \
    make install

########################
# Installing rrapper 
########################

WORKDIR rrapper/

# install rrdump
RUN pip install ./rrdump

# install requirements.txt
RUN pip install -r requirements.txt

# run setup.py
RUN python setup.py install

########################
# Finalize
########################

USER crashsim
RUN rrinit
