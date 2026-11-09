//go:build ignore

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// SO_ORIGINAL_DST is the Linux socket option to get the original destination address
const SO_ORIGINAL_DST = 80

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run test_original_dst.go <host> <port>")
		fmt.Println("Example: go run test_original_dst.go 127.0.0.1 9900")
		os.Exit(1)
	}

	host := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid port number: %v\n", err)
		os.Exit(1)
	}

	// Connect to the proxy
	fmt.Printf("Connecting to %s:%d...\n", host, port)
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s:%d\n", host, port)
	fmt.Printf("Local address: %s\n", conn.LocalAddr().String())
	fmt.Printf("Remote address: %s\n", conn.RemoteAddr().String())

	// Get the file descriptor
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		fmt.Println("Not a TCP connection")
		os.Exit(1)
	}

	file, err := tcpConn.File()
	if err != nil {
		fmt.Printf("Failed to get file descriptor: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	fd := int(file.Fd())
	fmt.Printf("File descriptor: %d\n", fd)

	// Try to get the original destination
	fmt.Println("Attempting to get original destination using SO_ORIGINAL_DST...")

	// Create a buffer to hold the sockaddr structure
	// The sockaddr_in structure is 16 bytes
	buf := make([]byte, 16)

	// Get the size of the buffer
	size := uint32(len(buf))

	// Call getsockopt
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if errno != 0 {
		fmt.Printf("Failed to get original destination: %v\n", errno)
		os.Exit(1)
	}

	// Parse the sockaddr structure
	// The sockaddr_in structure is:
	// struct sockaddr_in {
	//     sa_family_t    sin_family; /* address family: AF_INET */
	//     in_port_t      sin_port;   /* port in network byte order */
	//     struct in_addr sin_addr;   /* internet address */
	// };

	// Print the raw data
	fmt.Printf("Raw sockaddr data: %v\n", buf)

	// Extract the address family
	family := uint16(buf[0]) | uint16(buf[1])<<8
	fmt.Printf("Address family: %d\n", family)

	// Extract the port (network byte order)
	port = int(buf[2])<<8 | int(buf[3])
	fmt.Printf("Port: %d\n", port)

	// Extract the IP address
	ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
	fmt.Printf("IP address: %s\n", ip.String())

	// Print the original destination
	fmt.Printf("Original destination: %s:%d\n", ip.String(), port)

	// Send a simple HTTP CONNECT request to test the proxy
	fmt.Println("\nSending HTTP CONNECT request...")
	request := fmt.Sprintf("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	_, err = conn.Write([]byte(request))
	if err != nil {
		fmt.Printf("Failed to send request: %v\n", err)
		os.Exit(1)
	}

	// Read the response
	fmt.Println("Reading response...")
	buf = make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Failed to read response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response (%d bytes):\n%s\n", n, string(buf[:n]))

	fmt.Println("Test completed successfully.")
}
