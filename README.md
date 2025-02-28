# ctools

ctools is a powerful command-line toolkit built in Rust 🚀 that bundles a diverse range of utilities into a single application. Whether you need random generators, text manipulation, file operations, networking tools, system diagnostics, or even encryption utilities, ctools has you covered!

## Features

- 🎲 **Random Generators**  
  Generate random strings, integers, floats, UUIDs, and strong passwords.

- 🔠 **Text Utilities**  
  Hash text with MD5, SHA-256, or SHA-512, encode/decode Base64, reverse text, and measure text length.

- 📁 **File Utilities**  
  Retrieve file size, compute file hashes, count files in directories, and search for files matching a pattern.

- 🌐 **Networking Tools**  
  Fetch your public IP, perform IP lookups, scan ports, ping hosts, and perform DNS lookups.

- ⏰ **Time & Date Utilities**  
  Get the current date and time, epoch time, convert timestamps, and run countdown timers.

- 🔢 **Math & Conversion Tools**  
  Evaluate mathematical expressions, convert bytes to human-readable units, and convert temperatures.

- 🖥️ **System Utilities**  
  Display system info (OS, CPU, RAM), check uptime, disk usage, list running processes, and kill processes.

- 🔐 **Security & Encryption**  
  Encrypt and decrypt text using AES and decode JWT tokens.

- 🌍 **Web & API Tools**  
  Make HTTP GET/POST requests, shorten URLs, and generate QR codes.

- 😄 **Miscellaneous**  
  Fetch weather updates, display random jokes and fortunes, generate Lorem Ipsum text, and pick random colors.

## Getting Started

Clone the repository and build with Cargo:

```bash
git clone https://github.com/k-gasiewski/ctools.git
cd ctools
cargo build --release
```

## Usage

Run the built executable with the desired subcommand. For example, to generate a random string of 10 characters:

```bash
./target/release/ctools random string 10
```

## Contributions

Contributions are welcome! Feel free to fork the repository, open issues, and submit pull requests.
