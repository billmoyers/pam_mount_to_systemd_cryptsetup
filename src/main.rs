#![warn(missing_docs)]

//! This is used in `pam_mount.conf.xml` to mount volumes via `systemd-cryptsetup`
//! with a stanza like:
//!
//! ```xml
//! <cryptmount>/usr/local/sbin/pam_mount_to_systemd_cryptsetup -- %(VOLUME)</cryptmount>
//! <cryptumount>/usr/local/sbin/pam_mount_to_systemd_cryptsetup -u -- %(VOLUME)</cryptumount>
//! ```
//!
//! This program will invoke the relevant `systemd` unit and send the password along from
//! `pam_mount` to the `systemd` responsible password agent.
//!
//! The password agent behavior comes from [[1]](https://systemd.io/PASSWORD_AGENTS/).

use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{self, Command};
use std::thread;
use std::time;
use io::{Error, ErrorKind};

use inotify::{Inotify, WatchMask, EventMask};
use libc::{mlock, c_void};

fn show_usage(program_name: String) {
	eprintln!("Send pam_mount password to systemd cryptsetup units.

USAGE:
    {} [OPTIONS] [--] MOUNTPOINT

OPTIONS:
    -u, --unmount         `stop` the systemd unit instead `start`ing it
        --timeout <N>     Timeout in seconds, default is \"10\" (seconds).
                          0 means wait indefinitely.
    -V, --verbose         Verbose logging of activity
", program_name);
}

/// The directory where systemd places password agent `ask.*` and `sck.*` files per [1].
pub static WATCH_PATH: &'static str = "/run/systemd/ask-password/";

/// Stores relevant fields from the `ask.*` files.
struct AskFile {
	location: String,
	name: String,
	socket_path: String,
	mount_point: String,
	pid: String,
	message: String,
}

/// TODO: This parsing could probably be improved still without using an external crate.
fn read_ask_file(read: &mut dyn io::Read) -> io::Result<AskFile> {
	let mut ask = AskFile {
		location: String::from(""),
		name: String::from(""),
		socket_path: String::from(""),
		mount_point: String::from(""),
		pid: String::from(""),
		message: String::from(""),
	};

	let reader = io::BufReader::new(read);
	for line in reader.lines() {
		match line {
			Ok(line) => {
				//[1]: Make sure to ignore unknown .ini file keys in those files, so that we can easily extend the format later on.
				//[1]: The socket to send the response to is configured via Socket= in the [Ask] section. It is a AF_UNIX/SOCK_DGRAM socket in the file system.
				if line.starts_with("Socket=") {
					ask.socket_path = line[7..].to_owned();
				}
				else if line.starts_with("PID=") {
					ask.pid = line[4..].to_owned();
				}
				//TODO This probably isn't as generically true as I think.
				//Make sure the `ask.*` file's `Message` field looks correct. An example of what might be expected for user 'bob' is:
				//  "Please enter passphrase for disk ubuntu--vg-bob (decrypt_bob) on /home/bob:"
				else if line.starts_with("Message=") {
					ask.message = line[8..].to_owned();
					let tmp = ask.message.replace(":", "").replace("(", "").replace(")", "");
					let tokens: Vec<&str> = tmp.split(' ').fuse().collect();
					match tokens[..] {
						//TODO: Handle other languages if systemd is localized at all, seems maybe not per [this](https://github.com/systemd/systemd/blob/main/src/cryptsetup/cryptsetup.c).
						["Please", "enter", "passphrase", "for", "disk", _lv_name, _cryptname, "on", path] => ask.mount_point = path.to_string(),
						_ => {},
					}
				}
			},
			_ => {},
		}
	}

	if ask.mount_point == "" {
		Err(Error::new(ErrorKind::Other, "Did not find mount point in ask file"))
	} 
	else if ask.socket_path == "" {
		Err(Error::new(ErrorKind::Other, "Did not find socket path in ask file"))
	} 
	else {
		Ok(ask)
	}
}

/// Read a password "securely" from a stream and prepare the correct message
/// to send to the password agent's socket per [1].
fn read_to_agent_message(read: &mut dyn io::Read, verbose: bool) -> io::Result<Vec<u8>> {
	//TODO: Warn somewhere that it may not work for extremely long passwords?
	let max_password_len: usize = 1024;

	//`mlock` some memory
	let mut message_buffer = Vec::with_capacity(max_password_len+1);
	if verbose {
		eprintln!("Calling mlock on {} bytes", max_password_len+1);
	}
	let ptr = message_buffer.as_ptr() as *const c_void;
	let ret = unsafe { mlock(ptr, message_buffer.len()) };
	assert_eq!(ret, 0);

	//Read the password into that `mlock`ed memory
	message_buffer.push(b'+'); //See [1] for the reasoning for prefixing the '+' character.
	read.read_to_end(&mut message_buffer)?;
	Ok(message_buffer)
}

/// Watch for `systemd` ask password request files being generated. When one appears,
/// validate that it seems to be correct for the given directory being mounted and if so,
/// send the password message.
fn process_asks(watch_path: &str, for_mount_point: &str, message_buffer: &Vec<u8>, verbose: bool, require_socket_owner_uid: u32) -> io::Result<bool> {
	//[1]: Create an inotify watch on /run/systemd/ask-password, watch for IN_CLOSE_WRITE|IN_MOVED_TO
	let mut inotify = Inotify::init()
		.expect("Error while initializing inotify instance");

	if verbose {
		eprintln!("Watching \"{}\" via inotify...", watch_path);
	}
	inotify
		.add_watch(watch_path, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE)
		.expect(format!("Failed to watch {}", watch_path).as_str());

	let mut alive = true;
	while alive {
		if verbose {
			eprintln!("Reading inotify events...");
		}
		let mut buffer = [0; 4096];
		let events_ret = inotify.read_events_blocking(&mut buffer);

		if let Ok(events) = events_ret {
			for event in events {
				if verbose {
					eprintln!("Got inotify event...");
				}
				if let Some(os_name) = event.name {
					if let Some(name) = os_name.to_str() {
						//[1]: Ignore all events on files in that directory that do not start with "ask."
						if name.starts_with("ask.") {
							//[1]: Make sure to hide a password query dialog as soon as a) the ask.xxxx file is deleted, watch this with inotify. b) the NotAfter= time elapses, if it is set != 0.
							if event.mask.contains(EventMask::DELETE) {
								//TODO: Cancel, but how to know which user was attempting on that file other than storing a map?
							}

							//[1]: As soon as a file named “ask.xxxx” shows up, read it. It’s a simple .ini file that may be parsed with the usual parsers. The xxxx suffix is randomized.
							if verbose {
								eprintln!("Parsing {}...", name);
							}

							let file = File::open(format!("{}/{}", watch_path, name)).unwrap();
							let mut reader = io::BufReader::new(file);
							let mut ask = read_ask_file(&mut reader)
								.expect("Failed parsing ask file");
							ask.location = String::from(watch_path);
							ask.name = String::from(name);

							if ask.mount_point != for_mount_point {
								if verbose {
									eprintln!("  mount point mismatch: ask={} input={}", ask.mount_point, for_mount_point);
								}
								continue;
							}

							//Validate that `ask.socket_path` is under `watch_path`
							let sp = Path::new(&ask.socket_path);
							if !sp.starts_with(watch_path) {
								if verbose {
									eprintln!("  Socket={} which is not under {}, ignoring.", ask.socket_path, watch_path);
								}
								continue;
							}

							//Validate that `ask.socket_path` is owned by root / requires special privileges per [1].
							let stat = fs::metadata(sp)?;
							if stat.uid() != require_socket_owner_uid {
								if verbose {
									eprintln!("  Socket={} is not owned by uid={}, ignoring.", ask.socket_path, require_socket_owner_uid);
								}
								continue;
							}
							//TODO: When no longer experimental, check: stat.file_type().is_socket_dgram()

							if verbose {
								eprintln!("  Socket={}", ask.socket_path);
							}

							//[1]: Ignore files where the time specified in the NotAfter= field in the [Ask] section is in the past. The time is specified in usecs, and refers to the CLOCK_MONOTONIC clock. If NotAfter= is 0, no such check should take place.
							//TODO: Implement this

							//[1]: If you do not want to use PK ensure to acquire the necessary privileges in some other way and send a single datagram to the socket consisting of the password string either prefixed with “+” or with “-” depending on whether the password entry was successful or not. You may but don’t have to include a final NUL byte in your message.
							if verbose {
								eprintln!("  sending message to socket {}...", ask.socket_path);
							}
							let socket = UnixDatagram::unbound().expect("UnixDatagram::unbound failed");
							socket.connect(ask.socket_path.clone())
								.expect(format!("Failed connecting to socket {}", ask.socket_path).as_str());
							socket.send(&message_buffer)
								.expect(format!("Failed sending to socket {}", ask.socket_path).as_str());
							alive = false;
							break;
						}
					}

					//TODO Handle any error conditions
				}
			}
		}
		else if let Err(e) = events_ret {
			eprintln!("{}", e);
		}
	}

	Ok(true)
}

fn main() {
	//Parse arguments.
	let mut timeout_millis = 10000;
	let mut verbose = false;
	let mut unmount = false;
	let mut double_dash = false;
	let mut problem = false;
	let mut last_arg: Option<String> = None;
	let args: Vec<String> = env::args().collect();
	if args.len() < 1 {
		show_usage("".to_string());
		return;
	}
	let program_name = args[0].clone();
	let mut skip = false;
	for i in 1..args.len() {
		if skip {
			skip = false;
			continue;
		}
		let arg = args[i].clone();
		if arg.starts_with("-") && !double_dash {
			match arg.as_str() {
				"--" => double_dash = true,
				"-u" | "--unmount" => if !unmount { 
					unmount = true
				} else {
					eprintln!("\"{}\" may only be specified once", arg);
					problem = true;
				},
				"-V" | "--verbose" => if !verbose { 
					verbose = true
				} else {
					eprintln!("\"{}\" may only be specified once", arg);
					problem = true;
				},
				"--timeout" => {
					if i+1 < args.len() {
						match args[i+1].parse::<u64>(){
							Ok(t) => timeout_millis = t*1000,
							Err(_) => problem = true,
						}
					}
					else {
						problem = true;
					}
					skip = true;
				},
				_ => {
					eprintln!("Problem at arg={}...", arg);
					problem = true;
				}
			}
		}
		else if i > 0 {
			match last_arg {
				Some(_) => {
					eprintln!("Last arg already set {}", arg);
					problem = true
				},
				_ => {
					last_arg = Some(arg.clone())
				}
			}
		}
	}
	if problem || last_arg.is_none() {
		show_usage(program_name);
		return;
	}

	if verbose {
		eprintln!("{} version {}", program_name, env!("CARGO_PKG_VERSION"));
	}

	//Convert the mount point into a systemd unit name.
	let target_unit = last_arg.unwrap();
	let mount_point = format!("/{}", &target_unit.replace("-", "/").replace(".mount", "")); //TODO: This could do the wrong thing if a username has a "-" in it, or probably other cases.

	//Spawn a thread which will exit the program after a timeout in case STDIN is never closed by the parent process
	//or no suitable agent socket can be found.
	if timeout_millis > 0 {
		if verbose {
			eprintln!("Setting a timer to exit after {} milliseconds.", timeout_millis);
		}
		thread::spawn(move || {
			thread::sleep(time::Duration::from_millis(timeout_millis));
			process::exit(1);
		});
	}

	let mut message_buffer = vec![];

	if !unmount {
		//Read the password from stdin into mlock'ed memory.
		message_buffer = read_to_agent_message(&mut io::stdin(), verbose)
			.expect("Failed reading stdin");
		if verbose {
			eprintln!("Prepared message from stdin..."); 
		}
	}

	//Execute systemctl command.
	if !unmount {
		if verbose {
			eprintln!("/usr/bin/systemctl start {}", target_unit);
		}
		Command::new("/usr/bin/systemctl")
			.arg("start")
			.arg(target_unit)
			.spawn()
			.expect("Failed to spawn systemctl process");

		//TODO: Can we present some message on DBus while waiting for the inotify so
		//people know what's going on?

		//Check for an agent socket.
		process_asks(WATCH_PATH, &mount_point, &message_buffer, verbose, 0)
			.expect("Error while watching");

		//TODO: See if there's a "secure memory" concept that could be used besides mlock, although really pam_mount
		//appears to just rely on mlock anyway.

		//Clear secure memory.
		message_buffer.fill(0);
	}
	else {
		if verbose {
			eprintln!("/usr/bin/systemctl stop {}", target_unit);
		}
		Command::new("/usr/bin/systemctl")
			.arg("stop")
			.arg(target_unit)
			.output()
			.expect("Failed to run systemctl process");
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Write;

	#[test]
	fn test_parse_ask_file() {
		let ask_text_1 = String::from("
[Ask]
PID=24384
Socket=sck.test_parse_ask_file
Message=Please enter passphrase for disk ubuntu--vg-bob (decrypt_bob) on /home/bob:
		");
		let ask1 = read_ask_file(&mut ask_text_1.as_bytes()).unwrap();
		assert_eq!(ask1.socket_path, "sck.test_parse_ask_file");
		assert_eq!(ask1.mount_point, "/home/bob");
		assert_eq!(ask1.pid, "24384");
		assert_eq!(ask1.message, "Please enter passphrase for disk ubuntu--vg-bob (decrypt_bob) on /home/bob:");
	}

	#[test]
	fn test_read_password() {
		let pw = "foobar";
		let v = read_to_agent_message(&mut pw.as_bytes(), true).unwrap();
		assert_eq!(vec![
			b'+',
			b'f',
			b'o',
			b'o',
			b'b',
			b'a',
			b'r'
		], v);
		//TODO: Some way to memdump or force swap and make sure the password doesn't appear?
	}

	#[test]
	fn test_inotify() {
		eprintln!("test_inotify entered");

		let tmp_path = "target/test_inotify";

		let socket_path_1 = "target/test_inotify/sck.test_inotify.1";
		let ask_path_1 = "target/test_inotify/ask.test_inotify.1";
		let ask_text_1 = "[Ask]
PID=11111
Socket=target/test_inotify/sck.test_inotify.1
Message=Please enter passphrase for disk ubuntu--vg-bob (decrypt_bob) on /home/bob:";

		let socket_path_2 = "target/test_inotify/sck.test_inotify.2";
		let ask_path_2 = "target/test_inotify/ask.test_inotify.2";
		let ask_text_2 = "[Ask]
PID=11112
Socket=target/test_inotify/sck.test_inotify.2
Message=Please enter passphrase for disk ubuntu--vg-alice (decrypt_alice) on /home/alice:";

		//TODO: mkdir target/test_inotify

		let message_buffer: Vec<u8> = vec![
			b'+',
			b'b',
			b'o',
			b's',
			b'b',
			b'o',
			b'!',
		];
		let mbcp = message_buffer.clone();

		thread::spawn(move || {
			eprintln!("thread calling process_asks");
			let mut uid;
			unsafe { uid = libc::getuid(); }
			process_asks(tmp_path, "/home/bob", &mbcp, true, uid)
				.expect("Failed to watch");
		});
		thread::sleep(time::Duration::from_millis(1000));

		//Create an "ask" for Alice.
		if std::path::Path::new(socket_path_2).exists() {
			std::fs::remove_file(socket_path_2)
				.expect("Failed to remove file");
		}

		eprintln!("binding to socket");
		let sock2 = UnixDatagram::bind(socket_path_2)
			.expect("Failed to bind to socket");

		{
			let mut file = File::create(ask_path_2)
				.expect("failed creating ask file");
			file.write_all(ask_text_2.as_bytes())
				.expect("failed to write to ask file");
		}

		//Create an "ask" for Bob.
		if std::path::Path::new(socket_path_1).exists() {
			std::fs::remove_file(socket_path_1)
				.expect("Failed to remove file");
		}

		eprintln!("binding to socket");
		let sock1 = UnixDatagram::bind(socket_path_1)
			.expect("Failed to bind to socket");

		{
			let mut file = File::create(ask_path_1)
				.expect("failed creating ask file");
			file.write_all(ask_text_1.as_bytes())
				.expect("failed to write to ask file");
		}

		eprintln!("awaiting response on socket");

		let mut buf = vec![0; 16];
		sock1.recv(buf.as_mut_slice())
			.expect("recv failed");
		
		assert_eq!(buf[..7], message_buffer);
		assert_eq!(buf[7..], vec![0, 0, 0, 0, 0, 0, 0, 0, 0]);

		let mut buf2 = vec![0; 16];
		sock2.set_read_timeout(Some(time::Duration::from_millis(1000)))
			.expect("set_read_timeout failed");
		assert!(sock2.recv(buf2.as_mut_slice()).is_err());
		
		//TODO: Remove files
	}
}
