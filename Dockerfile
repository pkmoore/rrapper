FROM i386/ubuntu
ENV MAKEFLAGS="-j8"

########################
# Initialization
########################

# get necessary dependencies and cleanup
RUN apt-get update && apt-get -y install \
      ccache cmake make g++-multilib gdb libdw-dev \
      pkg-config coreutils python-pexpect manpages-dev git \
      ninja-build capnproto libcapnp-dev autoconf \
      libpython2.7-dev zlib1g-dev python-pip \
      gawk man libbz2-dev libunwind-dev

# get necessary CrashSimulator repos
RUN git clone -b spin-off https://github.com/pkmoore/rr
RUN git clone https://github.com/pkmoore/rrapper rr/rrapper

# create a new nonroot user
RUN useradd crashsim -m

########################
# Installing modified rr
########################

WORKDIR rr/

# compile and install the modified strace
RUN setarch i686 bash -c "cd third-party/strace && ./bootstrap && make && make install"

# compile and install rr
RUN setarch i686 bash -c "mkdir obj && cd obj && cmake .. && make install"

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

# (re)install man pages
RUN rm /etc/dpkg/dpkg.cfg.d/excludes
RUN apt-get install --reinstall -y manpages manpages-dev

USER crashsim
RUN env rrinit
