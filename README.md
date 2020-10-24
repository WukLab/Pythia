<p align="center">
<img src="https://github.com/WukLab/Pythia/blob/master/Documentation/logo.png" height="250" width="250">
</p>

__Pythia: Remote Oracles for the Masses (RDMA Side-Channel Attack)__

[__[USENIX Security 2019 Paper]__](https://www.usenix.org/system/files/sec19-tsai.pdf)
[__[Slide]__](./Documentation/Shin-Yeh-RDMASecurity-081519-UsenixSecurity.pdf)
[__[Talk]__](https://www.usenix.org/conference/usenixsecurity19/presentation/tsai)

## Pythia

Pythia is a set of __RDMA-based remote side-channel attacks__ that allow an attacker on one client machine to learn how victims on other client machines access data a server exports as an in-memory data service.  We reverse engineer the memory architecture of the most widely used Mellanox RDMA NIC and use this knowledge to improve the efficiency of Pythia. 

We evaluated Pythia both in a laboratory and in a public cloud (CloudLab) setting. Pythia is fast (_57 us_), accurate (_97% accuracy_), and can hide all its traces from the victim or the server.

## Testing

This version of Pythia has been tested for the following configuration:

1. Software
  * OS: CentOS 7.2 
  * RDMA drivers: MLNX_OFED_LINUX-4.3-1.0.1.0
2. Hardware
  * RNICs:
    * ConnectX-4 (InfiniBand)
3. Package (on CentOS7)
  * required packages: `memcached memcached-devel libmemcached libmemcached-devel numactl numactl-devel mbedtls mbedtls-devel glib2 glib2-devel `
  * add the following two lines to the end of /etc/security/limits.conf
    * `* soft memlock unlimited`
    * `* hard memlock unlimited`

### Prerequisites
1. Three machines connected via RDMA capable devices (server, victim, and attacker)

### S1: Setup MEMCACHED
Modify MEMCACHED_IP in rsec_base.h to server's IP

### S2: Setup setup.json
Modify setup.json to have correct device index and debug mode

### S3: Compile Pythia
make clean all

### S4: Run server
execute run_server.sh on server machine

### S5: Run client
execute run_client.sh on client machine

### S6: Run attacher
execute run_attacker.sh on attacker machine

It will show you the Pythia line in figure 7 in the paper.

### S7: CloudLab (optional)
in CloudLab, please change ibsetup.h to enable RoCE since CloudLab is using RoCE

CAUTION: cloudlab is using vlan for RoCE. Therefore, SGID is configured as 4. Please check https://community.mellanox.com/s/article/howto-configure-roce-on-connectx-4 for more details

## History:
`Pythia v0.1`: first opensource Pythia

## Cite

To cite Pythia, please use:

>\@inproceedings{USENIXSEC19-PYTHIA,  
> author = {Shin-Yeh Tsai and Mathias Payer and Yiying Zhang},  
> title = {Pythia: Remote Oracles for the Masses},  
> booktitle = {28th {USENIX} Security Symposium (Usenix SEC '19)},  
> year = {2019},  
> address = {Santa Clara, CA, USA},  
> month = {August}  
>}

## License:
Copyright (c) 2019 Wuklab, Shin-Yeh Tsai <shinyehtsai@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
