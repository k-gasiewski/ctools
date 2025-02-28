use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use evalexpr::eval;
use hex;
use md5;
use qrcode::QrCode;
use rand::Rng;
use reqwest;
use sha2::{Digest, Sha256, Sha512};
use std::error::Error;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessExt, System, SystemExt, DiskExt};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;
use uuid::Uuid;
use walkdir::WalkDir;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Parser)]
#[command(name = "ctools")]
struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	Random { #[command(subcommand)] command: RandomCommands },
	Text { #[command(subcommand)] command: TextCommands },
	File { #[command(subcommand)] command: FileCommands },
	Ip { #[command(subcommand)] command: IpCommands },
	PortScan { ip: String, port_range: String },
	Ping { host: String },
	DnsLookup { domain: String },
	Time { #[command(subcommand)] command: TimeCommands },
	Countdown { seconds: u64 },
	Calc { expression: String },
	Convert { #[command(subcommand)] command: ConvertCommands },
	Sys { #[command(subcommand)] command: SysCommands },
	EncryptAes { key: String, text: String },
	DecryptAes { key: String, text: String },
	JwtDecode { token: String },
	Http { #[command(subcommand)] command: HttpCommands },
	UrlShorten { url: String },
	QrGenerate { text: String },
	Weather { city: String },
	Joke,
	Fortune,
	Lorem { words: usize },
	ColorRandom,
}

#[derive(Subcommand)]
enum RandomCommands {
	String { length: usize },
	Int { min: i64, max: i64 },
	Float { min: f64, max: f64 },
	Uuid,
	Password { length: usize },
}

#[derive(Subcommand)]
enum TextCommands {
	Hash { algorithm: String, text: String },
	Base64Encode { text: String },
	Base64Decode { text: String },
	Reverse { text: String },
	Length { text: String },
}

#[derive(Subcommand)]
enum FileCommands {
	Size { filepath: String },
	Hash { algorithm: String, filepath: String },
	Count { directory: String },
	Search { directory: String, pattern: String },
}

#[derive(Subcommand)]
enum IpCommands {
	Public,
	Lookup { ip: String },
}

#[derive(Subcommand)]
enum TimeCommands {
	Now,
	Epoch,
	Convert { timestamp: i64 },
}

#[derive(Subcommand)]
enum ConvertCommands {
	Bytes { value: u64 },
	Temperature { value: f64, unit: String },
}

#[derive(Subcommand)]
enum SysCommands {
	Info,
	Uptime,
	Disk,
	Processes,
	Kill { pid: i32 },
}

#[derive(Subcommand)]
enum HttpCommands {
	Get { url: String },
	Post { url: String, data: String },
}

fn main() -> Result<(), Box<dyn Error>> {
	let cli = Cli::parse();
	match cli.command {
		Commands::Random { command } => match command {
			RandomCommands::String { length } => {
				let s: String = rand::thread_rng()
					.sample_iter(&rand::distributions::Alphanumeric)
					.take(length)
					.map(char::from)
					.collect();
				println!("{}", s)
			}
			RandomCommands::Int { min, max } => {
				let n = rand::thread_rng().gen_range(min..=max);
				println!("{}", n)
			}
			RandomCommands::Float { min, max } => {
				let f = rand::thread_rng().gen_range(min..=max);
				println!("{}", f)
			}
			RandomCommands::Uuid => println!("{}", Uuid::new_v4()),
			RandomCommands::Password { length } => {
				let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
				let password: String = (0..length)
					.map(|_| {
						let idx = rand::thread_rng().gen_range(0..charset.len());
						charset[idx] as char
					})
					.collect();
				println!("{}", password)
			}
		},
		Commands::Text { command } => match command {
			TextCommands::Hash { algorithm, text } => match algorithm.to_lowercase().as_str() {
				"md5" => println!("{:x}", md5::compute(text)),
				"sha256" => {
					let mut hasher = Sha256::new();
					hasher.update(text.as_bytes());
					println!("{:x}", hasher.finalize())
				}
				"sha512" => {
					let mut hasher = Sha512::new();
					hasher.update(text.as_bytes());
					println!("{:x}", hasher.finalize())
				}
				_ => println!("Unsupported algorithm"),
			},
			TextCommands::Base64Encode { text } => {
				println!("{}", general_purpose::STANDARD.encode(text))
			}
			TextCommands::Base64Decode { text } => match general_purpose::STANDARD.decode(&text) {
				Ok(bytes) => println!("{}", String::from_utf8_lossy(&bytes)),
				Err(_) => println!("Invalid Base64 input"),
			},
			TextCommands::Reverse { text } => println!("{}", text.chars().rev().collect::<String>()),
			TextCommands::Length { text } => println!("{}", text.chars().count()),
		},
		Commands::File { command } => match command {
			FileCommands::Size { filepath } => match fs::metadata(&filepath) {
				Ok(meta) => println!("{}", meta.len()),
				Err(_) => println!("File not found"),
			},
			FileCommands::Hash { algorithm, filepath } => {
				let data = fs::read(&filepath);
				if let Ok(data) = data {
					match algorithm.to_lowercase().as_str() {
						"md5" => println!("{:x}", md5::compute(data)),
						"sha256" => {
							let mut hasher = Sha256::new();
							hasher.update(&data);
							println!("{:x}", hasher.finalize())
						}
						"sha512" => {
							let mut hasher = Sha512::new();
							hasher.update(&data);
							println!("{:x}", hasher.finalize())
						}
						_ => println!("Unsupported algorithm"),
					}
				} else {
					println!("File not found")
				}
			}
			FileCommands::Count { directory } => {
				let mut count = 0;
				for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
					if entry.file_type().is_file() {
						count += 1
					}
				}
				println!("{}", count)
			}
			FileCommands::Search { directory, pattern } => {
				for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
					if entry.file_type().is_file() {
						if let Some(name) = entry.file_name().to_str() {
							if name.contains(&pattern) {
								println!("{}", entry.path().display())
							}
						}
					}
				}
			}
		},
		Commands::Ip { command } => match command {
			IpCommands::Public => {
				let res = reqwest::blocking::get("https://api.ipify.org")?.text()?;
				println!("{}", res)
			}
			IpCommands::Lookup { ip } => {
				let url = format!("http://ip-api.com/json/{}", ip);
				let res = reqwest::blocking::get(&url)?.text()?;
				println!("{}", res)
			}
		},
		Commands::PortScan { ip, port_range } => {
			let parts: Vec<&str> = port_range.split('-').collect();
			if parts.len() != 2 {
				println!("Invalid port range")
			} else if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
				for port in start..=end {
					let addr = format!("{}:{}", ip, port);
					if let Ok(mut addrs) = addr.to_socket_addrs() {
						if let Some(addr) = addrs.next() {
							if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
								println!("Port {} is open", port)
							}
						}
					}
				}
			} else {
				println!("Invalid port numbers")
			}
		}
		Commands::Ping { host } => {
			let output = if cfg!(target_os = "windows") {
				Command::new("ping").args(&["-n", "1", &host]).output()
			} else {
				Command::new("ping").args(&["-c", "1", &host]).output()
			};
			if let Ok(output) = output {
				println!("{}", String::from_utf8_lossy(&output.stdout))
			} else {
				println!("Ping failed")
			}
		}
		Commands::DnsLookup { domain } => {
			let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
			let response = resolver.lookup_ip(domain)?;
			for ip in response {
				println!("{}", ip)
			}
		},
		Commands::Time { command } => match command {
			TimeCommands::Now => println!("{}", chrono::Local::now().to_rfc3339()),
			TimeCommands::Epoch => println!("{}", Utc::now().timestamp()),
			TimeCommands::Convert { timestamp } => {
				println!("{}", Utc.timestamp_opt(timestamp, 0).single().unwrap_or_else(|| Utc::now()))
			}
		},
		Commands::Countdown { seconds } => {
			for i in (1..=seconds).rev() {
				println!("{}", i);
				thread::sleep(Duration::from_secs(1))
			}
			println!("0")
		}
		Commands::Calc { expression } => match eval(&expression) {
			Ok(value) => println!("{}", value),
			Err(_) => println!("Invalid expression"),
		},
		Commands::Convert { command } => match command {
			ConvertCommands::Bytes { value } => {
				let kb = value as f64 / 1024.0;
				let mb = kb / 1024.0;
				let gb = mb / 1024.0;
				println!("{} Bytes = {:.2} KB = {:.2} MB = {:.2} GB", value, kb, mb, gb)
			}
			ConvertCommands::Temperature { value, unit } => match unit.to_lowercase().as_str() {
				"c" | "celsius" => {
					let f = value * 9.0 / 5.0 + 32.0;
					let k = value + 273.15;
					println!("{} °C = {} °F = {} K", value, f, k)
				}
				"f" | "fahrenheit" => {
					let c = (value - 32.0) * 5.0 / 9.0;
					let k = c + 273.15;
					println!("{} °F = {} °C = {} K", value, c, k)
				}
				"k" | "kelvin" => {
					let c = value - 273.15;
					let f = c * 9.0 / 5.0 + 32.0;
					println!("{} K = {} °C = {} °F", value, c, f)
				}
				_ => println!("Unsupported temperature unit"),
			},
		},
		Commands::Sys { command } => match command {
			SysCommands::Info => {
				let sys = System::new_all();
				println!("OS: {}", sys.name().unwrap_or_default());
				println!("Kernel: {}", sys.kernel_version().unwrap_or_default());
				println!("CPU cores: {}", sys.cpus().len());
				println!("Total RAM: {} KB", sys.total_memory())
			}
			SysCommands::Uptime => {
				let sys = System::new_all();
				println!("{}", sys.uptime())
			}
			SysCommands::Disk => {
				let sys = System::new_all();
				for disk in sys.disks() {
					println!(
						"{}: {} available of {}",
						disk.name().to_string_lossy(),
						disk.available_space(),
						disk.total_space()
					)
				}
			}
			SysCommands::Processes => {
				let mut sys = System::new_all();
				sys.refresh_processes();
				for (pid, process) in sys.processes() {
					println!("{}: {}", pid, process.name())
				}
			}
			SysCommands::Kill { pid } => {
				let mut sys = System::new_all();
				sys.refresh_processes();
				let target = sys.process(sysinfo::Pid::from(pid as usize));
				if let Some(proc) = target {
					if proc.kill() {
						println!("Process {} killed", pid)
					} else {
						println!("Failed to kill process {}", pid)
					}
				} else {
					println!("Process not found")
				}
			}
		},
		Commands::EncryptAes { key, text } => {
			let key_hash = Sha256::digest(key.as_bytes());
			let iv: [u8; 16] = rand::thread_rng().gen();
			let cipher = Aes256Cbc::new_from_slices(&key_hash, &iv).unwrap();
			let ciphertext = cipher.encrypt_vec(text.as_bytes());
			let mut output = iv.to_vec();
			output.extend(ciphertext);
			println!("{}", hex::encode(output))
		}
		Commands::DecryptAes { key, text } => {
			if let Ok(data) = hex::decode(text) {
				if data.len() < 16 {
					println!("Invalid data")
				} else {
					let (iv, ciphertext) = data.split_at(16);
					let key_hash = Sha256::digest(key.as_bytes());
					let cipher = Aes256Cbc::new_from_slices(&key_hash, iv).unwrap();
					match cipher.decrypt_vec(ciphertext) {
						Ok(plaintext) => println!("{}", String::from_utf8_lossy(&plaintext)),
						Err(_) => println!("Decryption failed"),
					}
				}
			} else {
				println!("Invalid hex input")
			}
		}
		Commands::JwtDecode { token } => {
			let parts: Vec<&str> = token.split('.').collect();
			if parts.len() < 2 {
				println!("Invalid token")
			} else {
				for part in &parts[0..2] {
					let padded = format!("{:0<width$}", part, width = ((part.len() + 3) / 4) * 4);
					if let Ok(decoded) = general_purpose::URL_SAFE.decode(&padded) {
						println!("{}", String::from_utf8_lossy(&decoded))
					} else {
						println!("Failed to decode segment")
					}
				}
			}
		}
		Commands::Http { command } => match command {
			HttpCommands::Get { url } => {
				let res = reqwest::blocking::get(&url)?.text()?;
				println!("{}", res)
			}
			HttpCommands::Post { url, data } => {
				let client = reqwest::blocking::Client::new();
				let res = client.post(&url).body(data).send()?.text()?;
				println!("{}", res)
			}
		},
		Commands::UrlShorten { url } => {
			let api_url = format!("http://tinyurl.com/api-create.php?url={}", url);
			let res = reqwest::blocking::get(&api_url)?.text()?;
			println!("{}", res)
		}
		Commands::QrGenerate { text } => {
			if let Ok(code) = QrCode::new(text.as_bytes()) {
				let matrix = code.render::<char>().quiet_zone(false).module_dimensions(2, 1).build();
				println!("{}", matrix)
			} else {
				println!("Failed to generate QR code")
			}
		},
		Commands::Weather { city } => {
			let url = format!("http://wttr.in/{}?format=3", city);
			let res = reqwest::blocking::get(&url)?.text()?;
			println!("{}", res)
		},
		Commands::Joke => {
			let res = reqwest::blocking::get("https://official-joke-api.appspot.com/random_joke")?
				.json::<serde_json::Value>()?;
			println!("{}", res)
		},
		Commands::Fortune => {
			let fortunes = [
				"You will have a great day",
				"Be cautious today",
				"An opportunity will arise",
				"Expect the unexpected",
				"Good news is coming",
			];
			let idx = rand::thread_rng().gen_range(0..fortunes.len());
			println!("{}", fortunes[idx])
		},
		Commands::Lorem { words } => {
			let lorem = "Lorem ipsum dolor sit amet consectetur adipiscing elit Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
				.split_whitespace()
				.collect::<Vec<&str>>();
			let mut output = Vec::new();
			for i in 0..words {
				output.push(lorem[i % lorem.len()])
			}
			println!("{}", output.join(" "))
		},
		Commands::ColorRandom => {
			let r: u8 = rand::thread_rng().gen();
			let g: u8 = rand::thread_rng().gen();
			let b: u8 = rand::thread_rng().gen();
			println!("HEX: #{:02X}{:02X}{:02X} RGB: ({}, {}, {})", r, g, b, r, g, b)
		},
	}
	Ok(())
}