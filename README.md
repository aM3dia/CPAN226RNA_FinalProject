# Raw Packet Sniffer & Protocol Analyzer

**Author:** Anupa Ragoonanan (n01423202)  
**Course:** CPAN 226 RNA  
**Date:** April 17, 2026  

## Project Description

A cross-platform raw packet sniffer that captures live network traffic and decodes protocol headers. The tool extracts and displays:

- **MAC Addresses** (Ethernet Layer 2)
- **TTL Values** (IP Layer 3)  
- **Port Numbers** (TCP/UDP Layer 4)

This project demonstrates understanding of network protocols, data encapsulation, and raw socket programming.

## Requirements

| Requirement | Minimum Version |
|-------------|-----------------|
| Python | 3.7 or higher |
| Scapy | 2.7.0 or higher |
| Operating System | Windows, macOS, or Linux |

## Installation

### Step 1: Install Python

Download and install Python 3.7+ from [python.org](https://python.org)

### Step 2: Install Scapy

Open a terminal or command prompt and run:

```bash
pip3 install scapy
