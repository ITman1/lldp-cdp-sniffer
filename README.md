LLDP & CDP sniffer
==============

Sniffer that captures LLDP and CDP packets and prints them on standard output. Sniffer can also generate fake LLDP or CDP packets for test purposes.

### Preview on [`YouTube`](https://www.youtube.com/watch?v=fN0VAAZINgw)

# Usage

```
./sniffer [-l|-s] -i <interface> [-c] [-t <int>] [-r <int>]
```
  
Flags:
- -i interface name
- -s mode of sending packets (without -c it sends LLDP and otherwise CDP)
- -l mode of listening on the interface
- -c sending CDP packets
- -t time how to long send fake packets
- -r interval of sending the fake packets in seconds

## Examples how to run
```
./sniffer -i eth1 -s -r 60    // Sends LLDP packets every 60 second
./sniffer -i eth1 -l          // Listens for LLDP packets
```

# Building
```
make              compile project - release version
make pack         packs all required files to compile this project    
make clean        clean temp compilers files    
make clean-all    clean all compilers files - includes project    
make clean-outp   clean output project files 
```
