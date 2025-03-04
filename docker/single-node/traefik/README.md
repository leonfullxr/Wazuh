# Single-Node Docker deployment with Traefik
This is a configuration environment to be able to setup a single-node docker environment
with a reverse proxy.

In this case, I used traefik, although you can use whatever you want...

This guide serves as a purpose to show and guide the setup process with a reverse 
proxy, which I haven't really found so far.

The purpose of the reverse proxy is to ensure remote connectivity from a public 
IP address. So basically have this wazuh host open to the internet for remote access.
