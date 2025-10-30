# cpp-ids-ips


Minimal, modular IDS-like project in C++ (libpcap). Designed for staged development and easy extension.


## Build


```bash
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
mkdir build && cd build
cmake ..
make -j$(nproc)

sudo ./cpp-ids-ips <interface> <rules_file>
# example
sudo ./cpp-ids-ips ens34 ../rules.txt