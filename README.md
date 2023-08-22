# raminspect

note: The documentation for 0.2.0 is in the process of building. In the meantime you can do a git clone and run cargo doc --open to view the latest docs.

A crate that allows for finding and replacing arbitrary memory in an arbitrary process on a Linux system (this could be useful for hacking, for example). You can find the documentation on [docs.rs](https://docs.rs/raminspect/latest/raminspect).

Note that this project is not yet in a stable state; expect breaking changes and bugs. If you find a bug in the crate or any of the example don't work on your machine please don't hesitate to file an issue so it can be fixed as soon as posssible.

## Demonstration of Functionality

![demo](https://github.com/PhilosophicalProgrammer/raminspect/assets/79514573/7c55e611-93ff-47cc-8a72-a00840991270)

### Running an Example

You should be able to run the `firefox_search` example if you have Firefox installed. To do so, start by opening an instance of Firefox and typing "Old search text" in the search bar. If all goes well, when you run the example as root using the command `sudo cargo run --example firefox_search --release`, it should be replaced with "New search text", although you will probably have to click on the search bar again in order for it to render the new text.
