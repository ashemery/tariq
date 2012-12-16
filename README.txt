A Hybrid Port Knocking System.

Tariq Overview:

Tariq is a new hybrid port-knocking technique, that uses Cryptography, Steganography, and Mutual Authentication to develop another security layer in front of any service that needs to be accessed from different locations around the globe. Tariq was developed using python and scapy to fulfil my Ph.D. Research. We had to use a new methodology that can communicate in an unseen manner, making TCP Replay Attacks hard to be issued against Tariq. We also wanted the implementation to listen to no ports, or bind itself to no socket for packets exchange, so that Tariq won't be exposed himself to a remote exploit. Tariq relies completely on Packet Crafting, as all packets sent and received are crafted to suite our needs.

What does Tariq mean ?

It means knocking, hammering or coming at night :)

الطَّرْقُ: الضَّرْبُ، أو بالمِطْرَقَةِ، بالكسر، والصَّكُّ، -- القاموس المحيط

Why Is Tariq Secure?

Tariq Server's code is very simple, and is written completely using scapy (python),
The code is concise enough to be easily audited,
Tariq needs root privileges to adjust iptables rules, and perform remote tasks,
Tariq does not listen on any TCP/UDP port, which means no sockets is used. Tariq uses scapy's capabilities to sniff the incoming traffic and uses Packet Crafting techniques to reply back to an legitimate client,
The communication protocol is a simple secure encryption scheme that uses GnuPG keys with Steganography constructions. An observer watching packets is not given any indication that the SYN packet transmitted by 'Tariq' is a port knocking request, but even if they knew, there would be no way for them to determine which port was requested to open, or what task was requested to be done as all of that is inserted into a png picture using Steganography and then encrypted using GnuPG keys,
Replaying the knock request later does them no good, and in fact does not provide any information that might be useful in determining the contents of future request. The mechanism works using a single packet for the mutual authentication.
Why Is Tariq Needed?

Any host connected to the Internet needs to be secured against unauthorized intrusion and other attacks. Unfortunately, the only secure system is one that is completely inaccessible, but, to be useful, many hosts need to make services accessible to other hosts. While some services need to be accessible to anyone from any location, others should only be accessed by a limited number of people, or from a limited set of locations. The most obvious way to limit access is to require users to authenticate themselves before granting them access. This is were Tariq comes in place. Tariq can be used to open ports on a firewall to authorized users, and blocking all other traffic users. Tariq can also be used to execute a remotely requested task, and finally for sure Tariq can close the open ports that have been opened by a previous TariqClient? request. Tariq runs as a port authentication service on the iptables firewall, which validates the identity of remote users and modifies firewall rules (plus other tasks) according to a mutual authentication process done between Tariq Server and a Tariq client. Tariq could be used for a number of purposes, including:

Making services invisible to port scans,
Providing an extra layer of security that attackers must penetrate before accessing or breaking anything important,
Acting as a stop-gap security measure for services with known unpatched vulnerabilities,
Providing a wrapper for a legacy or proprietary services with insufficient integrated security.
Howto Install Tariq?

Requirements
Python >= 2.6
python-imaging - Python Imaging Library (PIL)
GnuGP
Scapy
A recent Linux kernel with iptables (eg. 2.6)
Installation and Configuration
Configuring the Client
First we need to preparing GnuPG to be used, so you need to create a directory for gnupg and generate a pair of keys using the following commands: mkdir /etc/tariq/.client-gpg chmod 600 /etc/tariq/.client-gpg gpg --homedir /etc/tariq/.client-gpg –gen-key
You need to export client's public key: gpg --homedir /etc/tariq/.client-gpg -a --export tariq@arabnix.com > key.pub.txt
Edit the 'client.conf' file to specify the client gpg directory and the default gpg user: client_gpg_dir=/etc/tariq/.client-gpg user=tariq@arabnix.com
And specify the image directory used for steganography, containing at least 1 reasonable png image file, just like the one included as a sample 'sample.png': img_dir=/usr/share/TariqClient?/img
Now specify the default secret knock sequence to match the sequence configured on the tariq server.
secret_ports=10000,7456,22022,12121,10001
Note:
you may pass the gpg user and knock sequence as arguments to TariqClient? (see howto use section).
Configuring the Server
After installing the requirements, the first step is to download, unpack, and install Tariq. Tariq can be downloaded from: http://code.google.com/p/tariq/. Once this is done, we need to configure the server. We also need to prepare GnuPG. So you need to create a directory for gnupg using the following commands: mkdir /etc/tariq/.server-gpg chmod 600 /etc/tariq/.server-gpg
You need to import and trust the client(s) public key(s): gpg --homedir /etc/tariq/.server-gpg --import < client.pub.txt gpg --homedir /etc/tariq/.server-gpg --edit-key tariq@arabnix.com
Then select trust (5)
Preparing iptables
Create an iptables chain to be used by tariq server: iptables -P INPUT DROP iptables -N tariq iptables -A INPUT -j tariq iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
Optional:
you may specify a range of ports to be filtered (dropped) in case you are running normal services on the same box: iptables -A INPUT -p tcp -m tcp --dport 1000,65535 -j DROP iptables -A INPUT -p udp -m udp --dport 1000,65535 -j DROP iptables -A INPUT -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
IMPORTANT NOTE:
Do not use the REJECT target with tariq.
Now edit 'server.conf' and specify the correct sequence of ports, by using the secret_ports variable. Example: secret_ports=10000,7456,22022,12121,10001
Now specify the server's gpg path: server_gpg_dir=/etc/tariq/.server-gpg
Specify the iptables chain name you have created for tariq: iptables_chain=tariq
Now please adjust the iptables chain name used to open ports for a successful knock: open_tcp_port=-A tariq -s {ip} -p tcp -m state --state NEW -m tcp --dport {dport} -j ACCEPT open_udp_port=-A tariq -s {ip} -p udp -m state --state NEW -m udp --dport {dport} -j ACCEPT
Howto use Tariq?

To start running tariq server, just run the following command using user root:

./TariqServer
Now that you have tariq server running, the firewall rules configured on the server, and your profile installed on the client, you're ready to run some commands remotely or open some ports. Using user root, to open, for instance, ssh (22) on the remote server (example.com), all you simply need to do on the client, is run:

./TariqCleint -u tariq@arabnix.com example.com O 22
If you don't want to open a port but perform a remote command for instance restarting the httpd service on the box, you don't need to login remotely and do it yourself and still working with the default drop firewall. All you simply need to do on the client is run the following command:

./TariqCleint -u tariq@arabnix.com example.com E service httpd restart
Another example, here I'm sending an echo message to the box:

./TariqCleint -u tariq@arabnix.com example.com E echo “Hello, It's me tariq”
Finally to close the port you requested to open, all you need to do is:

./TariqCleint -u tariq@arabnix.com example.com C 22
Future Work (aka TODO):

Make installer (rpm/deb based package)
Check if client uses a passphrase gpg key
Make system work as a daemon (write init scripts)


contact: Ali Al-Shemery <ali@arabnix.com>

