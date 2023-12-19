# NAT64 Implementation for eBPF Testing

## Overview
The NAT64 implementation within this project serves as a crucial component for testing and profiling eBPF-based tracing and profiling software. 

The goal of a NAT64 is to facilitate communication between IPv6 and IPv4 nodes and vice versa, providing a flexible solution for protocol translation and management.

## Functionality

Upon receiving an IPv6 packet with a specified destination prefix (**64:ff9b::**), the software dynamically assigns an IPv4 address from a pool to the IPv6 host.
The software then initiates the translation of the IPv6 packet to IPv4, considering potential translations or modifications of protocols within the IP packet.
Once translation is complete, the software redirects the packet to the appropriate interface leading to the destination.

## Supported Protocols
The NAT64 implementation supports the following protocols:

- ICMP
- TCP
- UDP
- ICMP6

## Challenges and Workarounds
During development, challenges were encountered, particularly in calculating the checksum for ICMP packets. A workaround was implemented using an accumulation function, resulting in a reduced performance compared to using helper functions like bpf_csum_diff.

## To-Do List

Manual IPv4 Address Insertion: Currently, there is an error in parsing structs in Python for manually inserting IPv4 addresses to be translated into IPv6. This needs resolution.
Bi-directional Address Translation: Implement a second table to associate IPv4 addresses with their corresponding IPv6 addresses for enhanced performance.

## Conclusion
The NAT64 software functions effectively, enabling nodes to communicate seamlessly through message exchange on both IPv6 and IPv4 sides. Ongoing improvements will be explored as case studies for the primary objective of testing and profiling eBPF software, with a focus on performance enhancements.
