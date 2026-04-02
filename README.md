# Wireshark Etherbone Dissectors

This repository contains Etherbone dissectors for Wireshark.

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

### Checkout the tested Wireshark version

```bash
cd wireshark
git checkout 13e5e0fb7271190
```

### Modify CMakeLists.txt

Open CMakeLists.txt in the Wireshark root directory and locate:

`set(PLUGIN_SRC_DIRS`

Add the following entry:

`plugins/epan/etherbone`

Example:

```
set(PLUGIN_SRC_DIRS
  plugins/epan/ethercat
  plugins/epan/gryphon
  plugins/epan/irda
  plugins/epan/mate
  plugins/epan/opcua
  plugins/epan/profinet
  plugins/epan/stats_tree
  plugins/epan/transum
  plugins/epan/unistim
  plugins/epan/wimax
  plugins/epan/wimaxasncp
  plugins/epan/wimaxmacphy
  plugins/epan/dfilter/ipaddr
  plugins/epan/etherbone    # <-- new entry
  plugins/wiretap/usbdump
  plugins/codecs/G711
  plugins/codecs/l16_mono
  ${CUSTOM_PLUGIN_SRC_DIR}
)
```

### (optional) Install the packages and libraries required to build Wireshark

For Debian based distros (Debian, Ubuntu etc):

```
./tools/debian-setup.sh
```

For RPM based distros (RH, Centos, Fedora etc):

```
./tools/rpm-setup.sh
```

### Build Wireshark

```
cmake -DDUMPCAP_INSTALL_OPTION=capabilities .
make -j$(nproc)
```

**-DDUMPCAP_INSTALL_OPTION=capabilities** is necessary for non-root users to be able to capture on most systems.
