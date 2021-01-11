# A Hybrid Port Knocking System
The network security has become a primary concern on the Internet in order to provide protected communication between hosts/nodes in a hostile environment. In order to protect network resources, each service provider pose a number of nontrivial challenges to security design and set its own policies for accessing resources on the network. These challenges make a case for building security solutions that achieve both broad protection and desirable network performance in terms of minimum data overhead and delay. It is so crucial to have computationally cheap and simple defense mechanisms that allow early protection against all types of attacks. In particular, it becomes very common and useful to have multiple progressively stronger layers of security, rather than attempting to have a single perfect security layer.

### Port-Knocking History:
In computer networking, Port Knocking is a method of externally opening ports on a firewall by generating a connection attempt on a set of pre-specified closed ports. Once a correct sequence of connection attempts is received, the firewall rules are dynamically modified to allow the host which sent the connection attempts to connect over specific port(s) [1].

The problem today in the world full of security threats, it should be assumed that all traffic is monitored by an unknown third party as it travels across a network. Doggedly adhering to this viewpoint provides us with the fact that our knock sequence can be passively observed by an eavesdropping person in the middle of our connection and just replay the knock sequence to get the same response from the server (open port or perform a task). This problem is called “TCP Replay Attack”. So we had to find a solution were the knock sequence is not re-playable.


### Tariq Overview
Tariq is a new hybrid port-knocking technique, that uses Cryptography, Steganography, and Mutual Authentication to develop another security layer in front of any service that needs to be accessed from different locations around the globe. Tariq was developed using python and scapy to fulfil my Ph.D. Research. We had to use a new methodology that can communicate in an unseen manner, making TCP Replay Attacks hard to be issued against Tariq. We also wanted the implementation to listen to no ports, or bind itself to no socket for packets exchange, so that Tariq won't be exposed himself to a remote exploit. Tariq relies completely on Packet Crafting, as all packets sent and received are crafted to suite our needs.

Tariq is developed using python and scapy to fulfil my Ph.D. Research. I chose python, because its an easy to learn language and the code can be easily audited or studied by others. I had to use a new methodology that can communicate in an unseen manner, making TCP Replay Attacks hard to be issued against Tariq. I also wanted the implementation to listen to no ports, or bind itself to no socket for packets exchange, so that Tariq won't be exposed itself to a remote exploit. Tariq relies completely on Packet Crafting, as all packets sent and received are crafted to suite its needs. Tariq doesn't just open/close ports, it can be used to perform remote tasks without the need to login to the remote box where Tariq is installed. All data sent and recived by Tariq is hidden within a PNG image using steganogra-py [2], and encrypted using GnuPG. The current version of Tariq uses only the TCP protocol, but I am willing to make another version of Tariq were the user has the ability to choose the communication protocol used.

**Note:** This project was done to fulfill the requirements of my PhD. Thesis...

---
### What does Tariq mean?
It means knocking, hammering or coming at night :)
الطَّرْقُ: الضَّرْبُ، أو بالمِطْرَقَةِ، بالكسر، والصَّكُّ، -- القاموس المحيط

---
### Why Is Tariq Secure?
- Tariq Server's code is very simple, and is written completely using scapy (python),
- The code is concise enough to be easily audited,
- Tariq needs root privileges to adjust iptables rules, and perform remote tasks,
- Tariq does not listen on any TCP/UDP port, which means no sockets is used. Tariq uses scapy's capabilities to sniff the incoming traffic and uses Packet Crafting techniques to reply back to an legitimate client,
- The communication protocol is a simple secure encryption scheme that uses GnuPG keys with Steganography constructions. An observer watching packets is not given any indication that the SYN packet transmitted by 'Tariq' is a port knocking request, but even if they knew, there would be no way for them to determine which port was requested to open, or what task was requested to be done as all of that is inserted into a png picture using Steganography and then encrypted using GnuPG keys,
Replaying the knock request later does them no good, and in fact does not provide any information that might be useful in determining the contents of future request. The mechanism works using a single packet for the mutual authentication.

---
### Why Is Tariq Needed?
Any host connected to the Internet needs to be secured against unauthorized intrusion and other attacks. Unfortunately, the only secure system is one that is completely inaccessible, but, to be useful, many hosts need to make services accessible to other hosts. While some services need to be accessible to anyone from any location, others should only be accessed by a limited number of people, or from a limited set of locations. The most obvious way to limit access is to require users to authenticate themselves before granting them access. This is were Tariq comes in place. Tariq can be used to open ports on a firewall to authorized users, and blocking all other traffic users. Tariq can also be used to execute a remotely requested task, and finally for sure Tariq can close the open ports that have been opened by a previous TariqClient? request. Tariq runs as a port authentication service on the iptables firewall, which validates the identity of remote users and modifies firewall rules (plus other tasks) according to a mutual authentication process done between Tariq Server and a Tariq client. Tariq could be used for a number of purposes, including:
- Making services invisible to port scans,
- Providing an extra layer of security that attackers must penetrate before accessing or breaking anything important,
- Acting as a stop-gap security measure for services with known unpatched vulnerabilities,
- Providing a wrapper for a legacy or proprietary services with insufficient integrated security.

### Howto Install Tariq
- Check the installation page [here](installation)

Useful References:
- [1](http://en.wikipedia.org/wiki/Port_knocking/) Port Knocking
- [2](http://code.google.com/p/steganogra-py/) Steganography in Python 

### Contact Me
- Twitter [here](https://twitter.com/binaryz0ne)
- Email: "Ali Hadi" <dfir [at] protonmail [dot] com>
