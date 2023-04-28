package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/krolaw/dhcp4"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

var (
	remoteIP  = flag.String("remote", "", "Destination Server:Destination Port")
	localPort = flag.Int("port", 1900, "Local Port")
	mtu       = 1500
)

func main() {
	//remoteIPP := "10.0.0.1"
	//remoteIP := &remoteIPP

	channel := make(chan int)
	flag.Parse()
	if "" == *remoteIP {
		flag.Usage()
		log.Fatalln("No Destination IP found")
	}
	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     "192.168.1.10/24",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("V3 Interface allocated: ", ifce.Name())
	log.Println("MTU: ", mtu)

	// DHCP
	rand.Seed(time.Now().UnixNano())
	// Generate a random number between 1 and 255
	//log.Println("It maybe laggy if you keep getting a new IP, use ipconfig /renew to renew ur ip")

	/*
		//C
		ipEnding := rand.Intn(255) + 1
		assignedIP := net.ParseIP("192.168.1." + strconv.Itoa(ipEnding))
		subnetMask := net.ParseIP("255.255.255.0")
		serverIP := net.ParseIP("192.168.1.0") // DHCP Server IP, must not duplicate
	*/

	//B
	ipEnding := rand.Intn(255) + 1
	ipEnding2 := rand.Intn(255) + 1
	assignedIP := net.ParseIP("172.19." + strconv.Itoa(ipEnding2) + "." + strconv.Itoa(ipEnding))
	subnetMask := net.ParseIP("255.240.0.0")
	serverIP := net.ParseIP("172.17.0.0") // DHCP Server IP, must not duplicate

	/*
		//A
		ipEnding := rand.Intn(255) + 1
		ipEnding2 := rand.Intn(255) + 1
		ipEnding3 := rand.Intn(255) + 1
		assignedIP := net.ParseIP("10." + strconv.Itoa(ipEnding3) + "." + strconv.Itoa(ipEnding2) + "." + strconv.Itoa(ipEnding))
		subnetMask := net.ParseIP("255.0.0.0")
		serverIP := net.ParseIP("10.0.0.0") // DHCP Server IP, must not duplicate
	*/

	log.Println("Interface IP address: ", assignedIP)
	assignIP(ifce, assignedIP, subnetMask, serverIP)
	log.Println("Prep Stage completed")
	//ip := net.ParseIP("192.168.1.1")
	//fmt.Println(ip.String(), []byte(ip)[12:])

	// Create remote connection
	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s", *remoteIP))
	if nil != err {
		log.Fatalln("Unable to resolve remote addr:", err)
	}
	// listen to local socket
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", *localPort))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}
	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}
	defer lstnConn.Close()

	go send(lstnConn, ifce, remoteAddr)
	go receive(lstnConn, ifce)

	//to stuck the thread
	<-channel
}

func send(lstnConn *net.UDPConn, ifce *water.Interface, remoteAddr *net.UDPAddr) {
	var frame ethernet.Frame
	count := 0
	for {
		//log.Println(len(frame))
		frame.Resize(1500)
		_, err := ifce.Read([]byte(frame))
		if err != nil {
			log.Fatal(err)
		}
		lstnConn.WriteToUDP(frame, remoteAddr)
		count++
		if count%1000 == 0 {
			log.Println("Sent", count, " packets")
		}
	}
}

func receive(lstnConn *net.UDPConn, ifce *water.Interface) {
	buf := make([]byte, 1514)
	count := 0
	for {
		n, _, err := lstnConn.ReadFromUDP(buf)
		ifce.Write(buf[:n])
		if err != nil || n == 0 {
			//fmt.Println("Error: ", err)
			continue
		}
		count++
		if count%1000 == 0 {
			log.Println("Received", count, " packets")
		}
	}
}

const (
	UDP int = 17
)

func assignIP(ifce *water.Interface, assignedIP net.IP, subnetMask net.IP, serverIP net.IP) {
	log.Println("Assigning IP", assignedIP.String())
	log.Println("Subnet Mask", subnetMask.String())
	log.Println("DHCP Server Address", serverIP.String())

	if !assignedIP.IsPrivate() {
		log.Println("WARNING: Assigning IP that maybe is not in private")
	}
	//frame := make([]byte, 1508)

	//a := dhcp4.NewPacket(dhcp4.BootRequest)
	//fmt.Println(a.)
	assignedIPByte := []byte(assignedIP)[12:]

	var frame ethernet.Frame

	for {
		frame.Resize(1500)
		n, err := ifce.Read([]byte(frame))
		if err != nil {
			log.Fatal(err)
		}
		frame = frame[:n]
		if frame.Ethertype() == ethernet.IPv4 {
			header, _ := ipv4.ParseHeader(frame.Payload())
			if header.Dst.Equal(net.ParseIP("255.255.255.255")) && header.Src.Equal(net.ParseIP("0.0.0.0")) && header.Protocol == UDP {
				udpHeader := frame.Payload()[34-14 : 42-12]
				srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
				dstPort := binary.BigEndian.Uint16(udpHeader[2:4])

				// DHCP Packet
				if srcPort == 68 && dstPort == 67 {
					dhcpPacket := frame.Payload()[42-14:]
					req := dhcp4.Packet(dhcpPacket)
					options := req.ParseOptions()
					//fmt.Println(options)
					if t := options[dhcp4.OptionDHCPMessageType]; len(t) != 1 {
						// not a DHCP packet
						continue
					} else {
						// ok this is a DHCP packet, parse it
						reqType := dhcp4.MessageType(t[0])
						// parse the type
						//fmt.Println(reqType)
						if reqType == dhcp4.Discover {
							ifce.Write(genDHCP(req, dhcp4.Offer, assignedIP, subnetMask, serverIP))
						} else if reqType == dhcp4.Request {
							// in case that Request IP is different from what we expect
							// decline it
							nak := false
							// loop thru options
							for i, opt := range options {
								// if it is a requested ip field
								if i == dhcp4.OptionRequestedIPAddress {
									// check if requested != our assigned
									if !bytes.Equal(opt, assignedIPByte) {
										// decline and break
										ifce.Write(genDHCP(req, dhcp4.NAK, net.IP{opt[0], opt[1], opt[2], opt[3]}, subnetMask, serverIP))
										nak = true
										break
									}
								}
							}
							// request packet LGTM
							if !nak {
								// gen a ACK request and tell client success
								ifce.Write(genDHCP(req, dhcp4.ACK, assignedIP, subnetMask, serverIP))
								log.Println("DHCP Configuration Success")
								break
							}
						}
					}
				}

			}
		}
	}
}

func genDHCP(req dhcp4.Packet, response dhcp4.MessageType, assignedIP net.IP, subnetMask net.IP, serverIP net.IP) []byte {
	//assignedIPByte := []byte(assignedIP)[12:]
	subnetMaskByte := []byte(subnetMask)[12:]
	serverIPByte := []byte(serverIP)[12:]
	//fmt.Println(subnetMaskByte, serverIPByte)

	// DHCP Packet
	option := []dhcp4.Option{{
		Code:  dhcp4.OptionSubnetMask,
		Value: subnetMaskByte,
	},
	}
	//fmt.Println(req.Secs())
	// build a DHCP packet
	//42947295 = As Good as forever, no expiry
	reply := dhcp4.ReplyPacket(req, response, serverIPByte, assignedIP, 4294967295*time.Second, option)
	reply[8] = req.Secs()[0]
	reply[9] = req.Secs()[1]

	// reply
	//reply = reply[:len(reply)-10]
	// Calculate checksum
	udp := udphdr{
		src:  uint16(67),
		dst:  uint16(68),
		ulen: uint16(8 + len(reply)),
	}

	udp.udpchecksum([4]byte(serverIPByte), [4]byte{255, 255, 255, 255}, uint8(UDP), reply)
	//fmt.Println(udp.csum)

	// UDP Header
	udpHeaderReply := []byte{}
	b := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(b, 67) // Src
	udpHeaderReply = append(udpHeaderReply[:], b[:]...)
	binary.BigEndian.PutUint16(b, 68) // Dst
	udpHeaderReply = append(udpHeaderReply[:], b[:]...)
	binary.BigEndian.PutUint16(b, uint16(8+len(reply))) // DHCP Packet + 8 Byte UDP Header length
	udpHeaderReply = append(udpHeaderReply[:], b[:]...)
	binary.BigEndian.PutUint16(b, udp.csum) // Checksum
	udpHeaderReply = append(udpHeaderReply[:], b[:]...)

	// IPv4 Header
	iph := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0x00, // DSCP CS6
		ID:       0x00,
		TotalLen: ipv4.HeaderLen + len(reply) + len(udpHeaderReply),
		TTL:      128,
		Protocol: UDP,
		Src:      serverIP,
		Dst:      net.ParseIP("255.255.255.255"),
	}
	// Claculating checksum
	ipHeader, _ := iph.Marshal()
	iph.Checksum = int(checksum(ipHeader))
	ipHeader, _ = iph.Marshal()
	//fmt.Println(iph)

	// Ethernet frame
	finalPacket := []byte{}
	finalPacket = append([]byte{0x00, 0xfa, 0x80, 0xce, 0x96, 0x3e}, finalPacket...) // Src MAC Address, MUST NOT DUPLICATE WITH NIC ADDRESS
	finalPacket = append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, finalPacket...) // Dst BROADCAST ADDRESS
	finalPacket = append(finalPacket, []byte{0x08, 0x00}...)                         // ETH Header
	finalPacket = append(finalPacket, ipHeader...)                                   // IP Header
	finalPacket = append(finalPacket, udpHeaderReply...)                             // UDP Header
	finalPacket = append(finalPacket, reply...)                                      // DHCP Payload
	//ifce.Write(finalPacket)
	return finalPacket
}

func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

type udphdr struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

func (u *udphdr) udpchecksum(src [4]byte, dst [4]byte, proto uint8, payload []byte) {
	u.csum = 0
	phdr := pseudohdr{
		ipsrc:   src,
		ipdst:   dst,
		zero:    0,
		ipproto: proto,
		plen:    u.ulen,
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, &phdr)
	binary.Write(&b, binary.BigEndian, u)
	binary.Write(&b, binary.BigEndian, &payload)
	u.csum = checksum(b.Bytes())
}
