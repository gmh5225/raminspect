# raminspect

A crate that allows for finding, replacing, and now in v0.3.0, even creating extra arbitrary memory in an arbitrary process on a Linux system. It also provides functions for the injection of arbitrary shellcode running in the processes' context. Essentially it's a library designed to make low-level hacking of a process easier. All of this requires root privileges, for obvious reasons.

## Demonstration of Functionality

![demo](https://github.com/PhilosophicalProgrammer/raminspect/assets/79514573/7c55e611-93ff-47cc-8a72-a00840991270)

### Running an Example

You should be able to run the `firefox_search` example if you have Firefox installed. To do so, start by opening an instance of Firefox and typing "Old search text" in the search bar. If all goes well, when you run the example as root using the command `sudo cargo run --example firefox_search --release`, it should be replaced with "New search text", although you will probably have to click on the search bar again in order for it to render the new text.

## A Note about Memory Allocation and Shell Injection

The find and replace functionality is available with or without the kernel module, but if you want to inject shellcode or allocate new buffers you must build and load the prerequisite kernel module first. You can do this by installing your distros' kernel headers package, performing a `git clone` and then running the following commands in the `kern_module` subfolder of the repository (if the build fails for some reason please file an issue):

```bash
make all
sudo insmod raminspect.ko
```

Also note that the shell injection part is currently designed to work on any architecture (even though the actual shell code itself has to be platform-specific), but the arbitrary memory allocation is currently limited to x86-64. PRs to add support for arbitrary allocation on more CPU architectures are welcome.

## A Note about Stability

This project is not yet in a stable state; expect breaking changes and bugs. If you find a bug in the crate or any of the examples don't work on your machine please don't hesitate to file an issue so it can be fixed as soon as possible.
