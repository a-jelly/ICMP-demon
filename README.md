## ICMP-demon - port knocking service based on ping packet analysis.

## Description
If you are a system administrator, you are probably tired of watching logs that are full of endless attempts of bots to log in to your server via SSH, and would like to get rid of them once and for all. This service implements the well-known technique of "port knocking" but not on the basis of analyzing access to different ports, but by checking the contents of incoming ping (ICMP) packets. With the same security level, this technique gives some advantages in usability due to the fact that it is accessible from almost any client, be it Linux, Windows, Mac or even Android cell phone. It does not require the remote administrator to have any additional tools other than the ping utility. ICMP demon working on the server side analyzes the content of incoming ICMP packets and performs actions described in the configuration file. For example, starting or stopping services, opening and closing specific ports in linux firewall.

### How does it work?

The ICMP demon listens to the RAW-socket on the server, and analyzes the contents of incoming ping packets. If the contents match one of those described in the configuration file and the source address is in allowed list, the daemon runs the script defined in the configuration file. There is protection against re-running (since ping generates more than one packet by default). 


## Example of use
Suppose we have already created a configuration file - config.toml, then it is enough to issue the command to run it:
```
sudo ./icmp_demon -c config.toml
```
Superuser rights are required for the daemon to listen to raw socket.

## Install from source

Download the source code from github-repo, install GCC and GNU make.
```
git clone https://github.com/a-jelly/ICMP-demon
cd ICMP-demon
make
make install
```    
The make install command will install the ICMP-demon service description file into ``/usr/lib/systemd/system`` and the daemon itself into ``/usr/local/sbin``
The configuration file in this case should be placed in ``/etc/icmp_demon/config.toml``

## Configuration

Here is an example of a configuration file:
```
# TOML-based config example
[log].
    use_syslog = 1 # Use system log.

[network]
    # bind_interface = "eth0"               
    # bind_address = "192.168.1.1"
    only_from = ["192.168.1.0/24", "192.168.2.0/24"]
    repeat_timeout = -1 # ICMP sequence 1 only
    # repeat_timeout = 5 # 5 sec. timeout for host
    ping_type = "all" # values: raw, 32bit, 64bit, all

[script.open]
    user = "root"
    group = "root"
    # content = "0pen_my_SSH"
    hex_content = "cafebabe"
    path = "/usr/local/sbin/ssh_port_open.sh" # script to open SSH port

[script.close]
    user = "root"
    group = "root"
    # content = "Cl0se_my_SSH"
    hex_content = "deadface"
    path = "/usr/local/sbin/ssh_port_close.sh" # script to close SSH port   
```
A few options need some explanation. To protect against repeated execution of the action (say, if the administrator forgets to specify the number of attempts in ping), there are two possibilities:
- specify a timeout in seconds during which packets from this address will be ignored.
- Set **repeat_timeout** = -1, in this case the daemon will consider only the first packet in the ICMP sequence.
  
The second interesting option is **ping_type**. It specifies which types of packets to analyze. Due to implementation peculiarities, an ICMP packet in 32-bit and 64-bit systems has a different format (different timestamp length). The daemon can react to each of them. There are also special utilities like nping that allow you to put any data into the data field of an ICMP packet. If you want to perceive such packets, use the "raw" option. If you want to analyze packets of all three types, use the "all" option. 
 
The scripts section describes each individual script that is launched by the daemon in case the content in the packet matches the one described in the script configuration. Content can be specified in two forms - **hex_content** - in hexadecimal form (for the **ping** utility) and in string form (if you want to use **nping**). Due to ping implementation peculiarities, the length of hex_content must be a multiple of 4 bytes (8 hexadecimal digits) - otherwise no match will occur. The rest of the fields are self-explanatory: the user and group on behalf of which the script is run and the path to the script.
	
## Use from a remote host.
Suppose your configuration is as specified in the configuration file and you want to access the server via SSH (SSH ports are closed by default).
Then all you need to do is issue the command:
```
ping -c2 -p cafebabe my.server.ip
```
Next, you can issue the command:
```
ssh my.server.ip
```
After the session is over, you should close the SSH port:
``` 
ping -c2 -p deadface my.server.ip
```

## Command line options
The following options are available:
```
	-c <cfg file> - specify configuration file
	-v {error|warning|info|debug} - specify event logging level
	-d - start in disconnected terminal mode
	-h - show help
```  

## Start and stop the service

To start in foreground use the command:
```
sudo ./icmp_demon -c config.toml
```
To start in systemd service mode use:
```
systemctl enable icmp-demon
systemctl start icmp-demon
```   
To stop the service, issue:
```
systemctl stop icmp-demon
```   
Be careful, if the configuration is incorrect or if you stop the ICMP demon and forget to enable SSH, you may lose remote access to the server.

## Contact 
Andrew Jelly - ajelly at gmail.com
