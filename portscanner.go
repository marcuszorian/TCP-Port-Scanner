package main
The program scans a specified host for open TCP ports using multiple goroutines and channels. It reports open ports along with common service names and supports scanning either well-known ports (1–1024) or the full range (1–65535).
import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// common ports sourced from https://www.uninets.com/blog/what-is-tcp-port

var common_ports = map[int]string{
	20:   "FTP Data",
	21:   "FTP Control",
	22:   "SSH/SCP",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	8080: "HTTP Alt",
	8443: "HTTPS Alt",
}

type PortRange struct {
	Start, End int
}

func getOpenPorts(hostname string, ports PortRange) {
	portChan := make(chan int, 100)
	resultChan := make(chan int, 100)
	var waitGroup sync.WaitGroup

	// Create 100 workers
	for i := 0; i < 100; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for port := range portChan {
				if scanPort(hostname, port) {
					resultChan <- port
				}
			}
		}()
	}

	// Feed ports to queue
	go func() {
		defer close(portChan)
		for i := ports.Start; i <= ports.End; i++ {
			portChan <- i
		}
	}()

	// Close results after workers done
	go func() {
		waitGroup.Wait()
		close(resultChan)
	}()

	// Collect + print open ports
	var openPorts []int
	for port := range resultChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)

	for _, port := range openPorts {
		if service, ok := common_ports[port]; ok { // ok indicates if a map value exists
			fmt.Printf("%d: %s (open)\n", port, service)
		} else {
			fmt.Printf("%d: unknown (open)\n", port)
		}
	}
}

func scanPort(hostname string, port int) bool { // Perform connect scan on port
	address := hostname + ":" + strconv.Itoa(port) // hostname:port
	conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond) // Attempts TCP connection to address, returning conn if successful or err otherwise
	if err != nil {
		return false
	}
	defer conn.Close() // close once the timeout has been finished | defer is used to delay execution until the above DialTimeout is finished
	return true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ./portscan <hostname> [full scan]")
		os.Exit(1)
	}
	hostname := os.Args[1]

	// Validate hostname
	if _, err := net.LookupIP(hostname); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid hostname %s: %v\n", hostname, err)
		os.Exit(1)
	}

	// Check for full flag (args[2])
	isFull := len(os.Args) > 2 && (os.Args[2] == "full" || os.Args[2] == "true")
	if isFull {
		getOpenPorts(hostname, PortRange{Start: 1, End: 65535})
	} else {
		getOpenPorts(hostname, PortRange{Start: 1, End: 1024})
	}
}
