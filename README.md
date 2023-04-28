# VirtualLAN

VirtualLAN is a software-defined network that allows you to connect multiple devices in a virtual network. This virtual network behaves the same as a physical local area network (LAN), allowing devices to communicate with each other as if they were connected to the same physical network.

## Features

- Easy setup and configuration
- Scalable network with support for large number of devices
- Low latency and high performance
- DHCP Sevrer build in
- UDP channel between two clients

## Requirement:
- Tap Driver installed (tap-windows-9.24.2-I601-Win10.exe)

## Usage of vlan:
```
  -port int
        Local Port (default 1900)
  -remote string
        Destination Server:Destination Port
```

## Example:
- (Computer 10.0.0.1)> vlan.exe -remote 10.0.0.2:1900
- (Computer 10.0.0.2)> vlan.exe -remote 10.0.0.1:1900

DHCP:
![image](https://user-images.githubusercontent.com/12872405/235243881-de36ca9b-c7d4-412c-9a54-b0f12dbde1ed.png)
![image](https://user-images.githubusercontent.com/12872405/235244003-c9cf7fc2-c09f-422a-a670-4c1f5a0d3243.png)

