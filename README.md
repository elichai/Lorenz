# lorenz
[![Build Status](https://travis-ci.org/elichai/lorenz.svg?branch=master)](https://travis-ci.org/elichai/lorenz)
[![Latest version](https://img.shields.io/crates/v/lorenz.svg)](https://crates.io/crates/lorenz)
![License](https://img.shields.io/crates/l/lorenz.svg)
[![dependency status](https://deps.rs/repo/github/elichai/lorenz/status.svg)](https://deps.rs/repo/github/elichai/lorenz)

A Rust binary for file encryption to multiple participants. 


## Installation

### Archlinux
TBD

### On Ubuntu_... and other Debian-based Linux distributions_
TBD

### On Gentoo
TBD
### From Snap
TBD

### On macOS
TBD

### On Windows
TBD

### From Sources
With Rust's package manager cargo, you can install Lorenz via:

```sh
cargo install --force lorenz
```

### From Binaries

The [release page](https://github.com/elichai/lorenz/releases) includes precompiled binaries for Linux, macOS and Windows.




# Usage

Generating keys: 
`lorenz generate-keys <amount>`

Encrypt a file: 
`lorenz encrypt <public-keys> <file>` 

Either of the associated private keys will be able to decrypt the file.
Decrypt:
`lorenz decrypt <private-key> <file>` 

# Example
```sh
$ lorenz generate-keys 3
key 1: 
privateKey: 0x40a8196f56f902d965fdf4eaadce44b651206bec8eed868d3c8b65df2f9df540
publicKey: 0x6fa09e7d6874dcb2410390636477d87cdc8a5bbf2f9d858337f8ff73e509d340

key 2: 
privateKey: 0x5814cdd862fd5704d3235dca766019372c3bf8d213a87ed867506af146dccd7e
publicKey: 0x6a27b32d6144888657b40328d3d6472127ea9835d7fd7a2c8327b0d72174737c

key 3: 
privateKey: 0x10d83487bdf1387fea1511005bb39a90d33a43f3d4bdcaa41261714abb5bcb52
publicKey: 0xc9f24018fc12249b65e5d0d1058c91f17b14979373621e25600ac1ae32b45738

$ lorenz encrypt 0x6fa09e7d6874dcb2410390636477d87cdc8a5bbf2f9d858337f8ff73e509d340 0x6a27b32d6144888657b40328d3d6472127ea9835d7fd7a2c8327b0d72174737c 0xc9f24018fc12249b65e5d0d1058c91f17b14979373621e25600ac1ae32b45738 test.txt

$ lorenz decrypt 0x10d83487bdf1387fea1511005bb39a90d33a43f3d4bdcaa41261714abb5bcb52 test.txt.lorenz

```
