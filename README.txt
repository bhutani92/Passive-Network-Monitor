1. We process the arguments using argc and argv and store them in variables "interface", "file", "str" and "expr".

2. If Interface is not provided, we lookup the default interface using pcap_lookupdev() API provided by pcap.h.

3. We get the network mask and network number using pcap_lookupnet() API.

4. Then the session is established based on interface name and the BPF expression is compiled and set as packets are to be listed based on the BPF expression when present.

5. Then all the packets are sniffed using pcap_loop() API and a callback is attached to parse those packets.

6. Based on the packet header attached to the callback, we check for the packet type and parse the packets based on whether it is IP packet, ARP packet, RARP packet or some other packet.

7. For all types, we check if the string supplied with -s argument is present in the packet payload. If yes, we continue parsing the packet otherwise, we return.

8. If the packet is valid and can be printed to the screen, we convert the timestamp to a proper printable format "yyyy-mm-dd hh:mm:ss.usec" using strftime() and print it to the screen.

9. Similarly, we convert the MAC address from Network Byte Order to Host Byte Order and print it. Then, ether type can be printed which is obtained earlier followed by length of header.

10. In case of TCP and UDP, src and dest ip addresses are retrieved and converted to Host Byte Order and printed along with their port number. In ICMP and Others, port numbers doesn't makes sense and hence are omitted. Finally, the printable characters in the payload are printed.

11. In case of ARP and RARP packets, everything is printed in the above fashion until header length. Finally, the printable characters in the payload are printed.

12. In case of IPv6 packets, the IPv6 header contains an extension header which is recursively searched until the value of next header field is 59 (which denotes there are no further packets). Finally, the printable characters in the payload are printed.

13. The established connection is closed once the desired number of packets are sniffed using pcap_close().

14. The memory allocated for all the variables is freed before exiting the function.

EXAMPLE OUTPUT:

sudo ./mydump -r hw1.pcap "port 80" | head -36
2013-01-12 22:30:48.832497 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 74 92.240.68.152:9485 -> 192.168.0.200:80 TCP
4500 003c a3d8 4000 3706 3ceb 5cf0 4498 E..<..@.7.<.\.D.
c0a8 00c8 250d 0050 ef75 982a 0000 0000 ....%..P.u.*....
a002 16d0 d064 0000 0204 05b4 0402 080a .....d..........
11e8 3eeb 0000 0000 0103 0309           ..>.........

2013-01-12 22:30:48.846741 00:0c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800 len 74 192.168.0.200:80 -> 92.240.68.152:9485 TCP
4500 003c 0000 4000 4006 d7c3 c0a8 00c8 E..<..@.@.......
5cf0 4498 0050 250d 7f92 4f83 ef75 982b \.D..P%...O..u.+
a012 3890 6327 0000 0204 05b4 0402 080a ..8.c'..........
009e eca6 11e8 3eeb 0103 0304           ......>.....

2013-01-12 22:30:48.908396 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 66 92.240.68.152:9485 -> 192.168.0.200:80 TCP
4500 0034 a3d9 4000 3706 3cf2 5cf0 4498 E..4..@.7.<.\.D.
c0a8 00c8 250d 0050 ef75 982b 7f92 4f84 ....%..P.u.+..O.
8010 000c 5978 0000 0101 080a 11e8 3efe ....Yx........>.
009e eca6                               ....

2013-01-12 22:30:48.908526 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 177 92.240.68.152:9485 -> 192.168.0.200:80 TCP
4500 00a3 a3da 4000 3706 3c82 5cf0 4498 E.....@.7.<.\.D.
c0a8 00c8 250d 0050 ef75 982b 7f92 4f84 ....%..P.u.+..O.
8018 000c 8c49 0000 0101 080a 11e8 3efe .....I........>.
009e eca6 4745 5420 6874 7470 3a2f 2f70 ....GET.http://p
6963 2e6c 6565 6368 2e69 742f 692f 6631 ic.leech.it/i/f1
3636 632f 3437 3932 3436 6230 6173 7474 66c/479246b0astt
6173 2e6a 7067 2048 5454 502f 312e 310a as.jpg.HTTP/1.1.
5573 6572 2d41 6765 6e74 3a20 7765 6263 User-Agent:.webc
6f6c 6c61 6765 2f31 2e31 3335 610a 486f ollage/1.135a.Ho
7374 3a20 7069 632e 6c65 6563 682e 6974 st:.pic.leech.it
0a0a 0069                               ...i

2013-01-12 22:30:48.908554 00:0c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800 len 66 192.168.0.200:80 -> 92.240.68.152:9485 TCP
4500 0034 a33d 4000 4006 348e c0a8 00c8 E..4.=@.@.4.....
5cf0 4498 0050 250d 7f92 4f84 ef75 989a \.D..P%...O..u..
8010 0389 631f 0000 0101 080a 009e ecb9 ....c...........
11e8 3efe


sudo ./mydump
2017-10-13 20:30:56.846739 70:f1:a1:f5:b5:ae -> 00:23:89:d8:b5:42 type 0x800 len 66 172.25.80.107:34792 -> 162.247.242.20:443 TCP
4500 0034 ee31 4000 4006 bb01 ac19 506b E..4.1@.@.....Pk
a2f7 f214 87e8 01bb e468 bb15 94be 91de .........h......
8010 dc0e f87b 0000 0101 080a e6dc c2a2 .....{..........
1844 ff1e                               .D..

2017-10-13 20:30:56.873628 00:23:89:d8:b5:42 -> 70:f1:a1:f5:b5:ae type 0x800 len 66 162.247.242.20:443 -> 172.25.80.107:34792 TCP
4500 0034 e345 4000 f006 15ed a2f7 f214 E..4.E@.........
ac19 506b 01bb 87e8 94be 91de e468 bb16 ..Pk.........h..
8010 6593 4c6d 0000 0101 080a 1845 af1e ..e.Lm.......E..
e6db 352c                               ..5,

2017-10-13 20:31:01.966725 70:f1:a1:f5:b5:ae -> 00:23:89:d8:b5:42 type 0x806 len 28
0001 0800 0604 0001 70f1 a1f5 b5ae ac19 ........p.......
506b 0000 0000 0000 ac19 5001           Pk........P.

2017-10-13 20:31:01.972887 00:23:89:d8:b5:42 -> 70:f1:a1:f5:b5:ae type 0x806 len 46
0001 0800 0604 0002 0023 89d8 b542 ac19 .........#...B..
5001 70f1 a1f5 b5ae ac19 506b 0000 0000 P.p.......Pk....
0000 0000 0000 0000 0000 0000 0000      ..............

2017-10-13 20:31:09.134742 70:f1:a1:f5:b5:ae -> 00:23:89:d8:b5:42 type 0x800 len 66 172.25.80.107:43172 -> 172.217.10.100:443 TCP
4500 0034 54f6 4000 4006 320c ac19 506b E..4T.@.@.2...Pk
acd9 0a64 a8a4 01bb 2bbc 37aa bbaf 7098 ...d....+.7...p.
8010 0193 6560 0000 0101 080a b0b0 91b2 ....e`..........
9f71 4025                               .q@%

2017-10-13 20:31:09.138550 00:23:89:d8:b5:42 -> 70:f1:a1:f5:b5:ae type 0x800 len 66 172.217.10.100:443 -> 172.25.80.107:43172 TCP
4500 0034 5bb5 0000 3b06 704d acd9 0a64 E..4[...;.pM...d
ac19 506b 01bb a8a4 bbaf 7098 2bbc 37ab ..Pk......p.+.7.
8010 00b4 6776 0000 0101 080a 9f71 f025 ....gv.......q.%
b0af e07a 				...z


sudo ./mydump -r hw1.pcap -s "HTTP" | head -25
2013-01-12 11:38:02.231699 c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 356 192.168.0.1:1901 -> 239.255.255.250:1900 UDP
4500 0180 dead 0000 0411 261c c0a8 0001 E.........&.....
efff fffa 076d 076c 016c bc0e 4e4f 5449 .....m.l.l..NOTI
4659 202a 2048 5454 502f 312e 310d 0a48 FY.*.HTTP/1.1..H
4f53 543a 2032 3339 2e32 3535 2e32 3535 OST:.239.255.255
2e32 3530 3a31 3930 300d 0a43 6163 6865 .250:1900..Cache
2d43 6f6e 7472 6f6c 3a20 6d61 782d 6167 -Control:.max-ag
653d 3336 3030 0d0a 4c6f 6361 7469 6f6e e=3600..Location
3a20 6874 7470 3a2f 2f31 3932 2e31 3638 :.http://192.168
2e30 2e31 3a38 302f 526f 6f74 4465 7669 .0.1:80/RootDevi
6365 2e78 6d6c 0d0a 4e54 3a20 7572 6e3a ce.xml..NT:.urn:
7363 6865 6d61 732d 7570 6e70 2d6f 7267 schemas-upnp-org
3a64 6576 6963 653a 496e 7465 726e 6574 :device:Internet
4761 7465 7761 7944 6576 6963 653a 310d GatewayDevice:1.
0a55 534e 3a20 7575 6964 3a75 706e 702d .USN:.uuid:upnp-
496e 7465 726e 6574 4761 7465 7761 7944 InternetGatewayD
6576 6963 652d 315f 302d 6334 3364 6337 evice-1_0-c43dc7
3137 3666 3962 3a3a 7572 6e3a 7363 6865 176f9b::urn:sche
6d61 732d 7570 6e70 2d6f 7267 3a64 6576 mas-upnp-org:dev
6963 653a 496e 7465 726e 6574 4761 7465 ice:InternetGate
7761 7944 6576 6963 653a 310d 0a4e 5453 wayDevice:1..NTS
3a20 7373 6470 3a61 6c69 7665 0d0a 5365 :.ssdp:alive..Se
7276 6572 3a20 5550 6e50 2f31 2e30 2055 rver:.UPnP/1.0.U
506e 502f 312e 3020 5550 6e50 2d44 6576 PnP/1.0.UPnP-Dev
6963 652d 486f 7374 2f31 2e30 0d0a 0d0a ice-Host/1.0....

