# nmap-tools

These tools are designed to work all together. The way we use these tools 
is using nmap-wrapper to scan IPs, nmap-diff then generated reports on 
the new ports opened. We can then use nmap-search to search the logs, 
and nmap report can be used to generat lists of hosts with a specific 
port open, or groups of hosts with a port or all ports, which then can 
be piped into other tools.
