# Wireshark Etherbone Dissectors

This repository contains Etherbone dissectors for Wireshark.
Tested with Wireshark v5.1.0 in Linux Mint 22.3.

## Building Wireshark with Etherbone Dissectors

### Clone the repositories

```bash
git clone https://github.com/wireshark/wireshark.git
git clone https://github.com/GSI-CS-CO/ebdissectors.git
```

### Add Etherbone dissectors to Wireshark

Copy the Etherbone plugin sources into the Wireshark plugin directory:

```bash
cp -r ebdissectors/plugins/epan/etherbone wireshark/plugins/epan/
```

### (optional) Install the packages and libraries required to build Wireshark

For Debian based distros (Debian, Ubuntu etc):

```
tools/os_setup/debian-setup.sh
```

For RPM based distros (RH, Centos, Fedora etc):

```
./tools/os_setup/rpm-setup.sh
```

### Build and install Wireshark

```
mkdir -p build
cmake -B build -DCMAKE_INSTALL_PREFIX="/opt/wireshark" -DCUSTOM_PLUGIN_SRC_DIR="plugins/epan/etherbone" -DDUMPCAP_INSTALL_OPTION=capabilities
cmake --build build --parallel "$(nproc)"
```

**-B build** : put build files in build/
**CMAKE_INSTALL_PREFIX** : install Wireshark under /opt/wireshark
**CUSTOM_PLUGIN_SRC_DIR** : include the Etherbone plugin
**-DUMPCAP_INSTALL_OPTION=capabilities** : necessary for non-root users to be able to capture on most systems (set capture capabilities on installed dumpcap).

Install into /opt/wireshark:

```
sudo cmake --install build
```

### Verify installation

/opt/wireshark/bin/tshark --version                       # TShark (Wireshark) 5.1.0 (v5.1.0rc0-1406-g04331b1b3134)
/opt/wireshark/bin/tshark -G plugins | grep -i etherbone  # check plugin
etherbone.so    	0.0.1	dissector	/opt/wireshark/lib/wireshark/plugins/5.1/epan/etherbone.so
getcap /opt/wireshark/bin/dumpcap                         # dumpcap capabilities
/opt/wireshark/bin/dumpcap cap_net_admin,cap_net_raw=ep

### Add Wireshark to PATH

Invoke

```
echo 'export PATH="/opt/wireshark/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify

```
which wireshark   # /opt/wireshark/bin/wireshark
which tshark      # /opt/wireshark/bin/tshark
which dumpcap     # /opt/wireshark/bin/dumpcap
```

### (optional) Add Wireshark to the Linux application menu (Linux Mint 22.3)

Cinnamon uses desktop entry files (.desktop) for applicaiton launchers.

Create the launcher:

```
mkdir -p ~/.local/share/applications
nano ~/.local/share/applications/wireshark-custom.desktop
```

Paste the content:

```
[Desktop Entry]
Version=1.0
Type=Application
Name=Wireshark (Custom Build)
GenericName=Network Protocol Analyzer
Comment=Analyze network traffic with Etherbone dissectors
Exec=/opt/wireshark/bin/wireshark %F
Icon=wireshark
Terminal=false
Categories=Network;Monitor;
StartupNotify=true
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
```

Make the launcher executable and finally refresh the applicaiton menu

```
chmod +x ~/.local/share/applications/wireshark-custom.desktop
update-desktop-database ~/.local/share/applications
```
