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
* a tun network device with address ::1 of your chunk and prefixlen 64, user set to the user you intent to run the server as
* IPv6 packet forwarding from internet facing interface to the tun device for your IPv6 address chunk
* tuntopipe to be executable and accessible from one of the locations in your server user's PATH
* JRE and IPv6DTLSTransport-...jar

Refer to the ipv6dtlstransport.sh script and ipv6dtlstransport.service definition files for how to actually start the server.
