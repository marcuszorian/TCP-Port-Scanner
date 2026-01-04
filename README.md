
# TCP Port Scanner

A simple TCP port scanner written in Go.

## Overview
The program scans a specified host for open TCP ports using multiple goroutines and channels. It reports open ports along with common service names and supports scanning either well-known ports (1–1024) or the full range (1–65535).

## Usage

```bash
go run main.go <hostname> [full]
# or
go build -o portscan main.go
./portscan <hostname> [full]
```

- Default: scans ports 1–1024  
- With `full`: scans ports 1–65535

## Example Output

```
$ ./portscan scanme.nmap.org
22: SSH/SCP (open)
80: HTTP (open)
```
