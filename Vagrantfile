# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  # we are using a 32-bit Ubuntu 16.04 virtualmachine
  # through libvirt
  config.vm.box = "bento/ubuntu-16.04-i386"

  # disable update checking to keep version consistencies
  config.vm.box_check_update = false 

  config.vm.provider :libvirt do |domain|
    domain.uri = 'qemu+unix:///system'
    domain.host = 'virtualized'
    domain.memory = 2048
  end
 
  # shell commands to run
  config.vm.provision "shell", inline: <<-SHELL

    # initialization
    apt-get update
    apt-get -y install ccache cmake make g++-multilib gdb libdw-dev \
                       pkg-config coreutils python-pexpect manpages-dev git \
                       ninja-build capnproto libcapnp-dev autoconf \
                       libpython2.7-dev zlib1g-dev python-pip
    apt-get clean && rm -rf /var/lib/apt/lists/*

    # CrashSimulator repo
    git clone https://github.com/pkmoore/rrapper
    git clone -b spin-off https://github.com/pkmoore/rr && cd rr/ 
    mkdir obj && cd obj && cmake .. && make -j8 && make install
    cd ../../rrapper
    pip install ./rrdump
    pip install -r requirements.txt
    python setup.py install
    rrinit

  SHELL
end
