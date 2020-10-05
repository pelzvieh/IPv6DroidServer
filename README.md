# IPv6DroidServer
A server component that runs IPv6Droid tunnels.

# Preparation of build
The project is known to build with Maven and OpenJDK 11, and it can be checked out from Eclipse as Maven project from SCM.

You need a certification authority in order to generate certificates for at least one server and the clients.

OpenSSL will be just fine, refer to the subcommands req and ca.

To build a valid server jar, you need to put three files into your project folder to
    src/main/resources/de/flyingsnail/ipv6server/dtlstransporter 
that will not be updated to the git repository:
* ca.cert will contain the PEM encoded root certificate of your CA
* dtlsserver.cert will contain the PEM encoded certificate for your server, signed by your CA
* dtlsserver.ky will contain the PEM encoded, unencrypted private key of your server, the public key of which is certified in dtlsserver.cert

# Build
    mvn install
should do the job for the java component.

Additionally a nearly trivial native component ''tuntopipe'' is required. Build it by
    gcc -o tuntopipe tuntopipe.c

# Running your own server
You need a (virtual) server with
* one public IPv4 address, either static, or resolvable by a public DNS name
* one public chunk of IPv6 adresses, strictly static, traffic to which is routed to one of your server's interfaces
(it is currently a hard coded assumption that the IPv6 address chunk is /64; feel free to submit a pull request to make this configurable)

On your server, set up
* a tun network device with address ::1 of your chunk and prefixlen 64, user set to the user you intent to run the server as (see an example below)
* IPv6 packet forwarding from internet facing interface to the tun device for your IPv6 address chunk
* tuntopipe to be executable and accessible from one of the locations in your server user's PATH
* JRE and IPv6DTLSTransport-...jar

Refer to the ipv6dtlstransport.sh script and ipv6dtlstransport.service definition files for how to actually start the server.

# Example network configuration
In case you're not experienced in setting up tun devices, here's an example on how to do this on a Linux server. We need to make some assumptions which are:
* the server is running Debian, using the classic network configuration ifupdown
* you have an /64 IPv6 address chunk to use, let's assume it is 2a06:dead:beef:affe::/64
* your server is going to run under the user ipv6server

Additional prerequisites are 
* a constant, static IPv4 address of your server, routed to a given network interface
* a working IPv6 setup of the server itself, including a routed IPv6 address on a given network interace
* routing set up such as that all traffic to 2a06:dead:beef:affe::/64 is sent to this interface
* a compute service that allows to set up a tun device (it might be a virtual machine service, might be running in the cloud, but a container service - for example - would require very specific set up from the provider)

These prerequisites are provided by your internet provider, plus the standard configuration of your server (usually DHCP for IPv4 interface, and SLAAC for IPv6 interface).

In this scenario, you have to add tun0 configuration to /etc/network/interfaces (or create a file with this content inside /etc/network/interfaces.d):

    auto tun0
    iface tun0 inet6 static
        pre-up ip tuntap add dev tun0 mode tun user ipv6server
        address 2a06:dead:beef:affe::1
        netmask 64
        scope global
        accept_ra 0
        autoconf 0
        post-down ip link del tun0

The command

    ifup tun0

should succeed.

If you're facing an error message like

    open: No such file or directory
    ifup: failed to bring up tun0

that might indicate that you're running within a linux container that lacks privilege to create device nodes and alternative setup of device inheritance. See the documentation of your container solution or ask your provider to extend the setup.
