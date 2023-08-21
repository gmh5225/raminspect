


# raminspect

A library that allows for the arbitrary reading and writing of any processes' memory on a Linux system (this could be useful for hacking, for example). Root privileges are required, for obvious reasons. You can find the documentation on [docs.rs](https://docs.rs/raminspect/latest/raminspect).

## Demonstration of Functionality

![demo](https://github.com/PhilosophicalProgrammer/raminspect/assets/79514573/25dbd418-8f56-451f-a778-6026eb0a253c)

## Important Notice

This project is in what could be called a pre-alpha state, and so the installation process may fail on some computers and the resulting kernel module may or may not be functional on others. If you notice a bug please file an issue so I can fix it as soon as possible.

## Getting Started

Before you can start using this library, you should also have the latest version of the mainline Linux kernel (if you don't have a custom kernel you can get this by just doing a system update on most distros) and your distros' corresponding linux-headers package installed. Here's how to install the Linux kernel headers on different distros:

### Arch Linux / Manjaro Linux

`sudo pacman -S linux-headers`

### Ubuntu / Debian

`sudo apt-get install linux-headers-generic`

### Fedora

`sudo dnf install kernel-headers`

Once you do this, you need to build and insert the required kernel module. To do so you can run these commands as root:

```bash
git clone https://github.com/PhilosophicalProgrammer/raminspect
cd raminspect/kern_module
make all
insmod raminspect.ko
```

After you do this you should be able to run the `firefox_search` example if you have Firefox installed. To do so, start by opening an instance of Firefox and typing "Old search text" in the search bar. If all goes well, when you run the example as root using the command `sudo cargo run --example firefox_search --release`, it should be replaced with "New search text", although you will probably have to click on the search bar again in order for it to render the new text.
