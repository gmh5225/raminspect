# raminspect

A library that allows for the arbitrary reading and writing of any processes' memory on a Linux system (this could be useful for hacking, for example). Root privileges are required, for obvious reasons. You can find the documentation on [docs.rs](https://docs.rs/raminspect/latest/raminspect).

## Demonstration of Functionality

![demo](https://github.com/PhilosophicalProgrammer/raminspect/assets/79514573/7c55e611-93ff-47cc-8a72-a00840991270)

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

Note that as of right now the huge page handling code in the kernel module does not work properly, and so you should run these commands as well to temporarily disable huge pages:

```bash
sudo bash -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled"
sudo bash -c "echo never > /sys/kernel/mm/transparent_hugepage/defrag"
```

This causes a slight performance penalty for the system, so you should either reboot to re-enable it later or run these commands after you're done using this:

```bash
sudo bash -c "echo always > /sys/kernel/mm/transparent_hugepage/enabled"
sudo bash -c "echo always > /sys/kernel/mm/transparent_hugepage/defrag"
```

After you do all this you should be able to run the `firefox_search` example if you have Firefox installed. To do so, start by opening an instance of Firefox and typing "Old search text" in the search bar. If all goes well, when you run the example as root using the command `sudo cargo run --example firefox_search --release`, it should be replaced with "New search text", although you will probably have to click on the search bar again in order for it to render the new text.
