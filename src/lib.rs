#![allow(unused_imports)] 
#![allow(dead_code)] 

use std::io::{TcpListener, TcpStream};
use std::io::{Acceptor, Listener};
use std::os::unix::prelude::AsRawFd;

mod bindings;
mod tls;

#[test]
fn it_works() {
	tls::tls_init();

	let cfg = tls::TLSConfig::new().unwrap();
	cfg.set_key_file("./server.key").unwrap();
	cfg.set_cert_file("./server.crt").unwrap();

	let server = tls::TLS::server().unwrap();
	server.configure(&cfg).unwrap();

	let mut listener = std::io::TcpListener::bind("127.0.0.1:4433").unwrap()
		.listen().unwrap();

	std::thread::Thread::spawn(move || {
		let cfg = tls::TLSConfig::new().unwrap();
		cfg.insecure_noverifycert();
		cfg.insecure_noverifyhost();

		let client = tls::TLS::client().unwrap();
		client.configure(&cfg).unwrap();

		client.connect("127.0.0.1", "4433").unwrap();

		let msg = "hello from client".to_string().into_bytes();
		client.write(&msg).unwrap();

		let buf = client.read(1024).unwrap();
		println!("client got: {}", std::str::from_utf8(buf.as_slice()));
	}).detach();

	let stream = listener.accept().unwrap();
	let conn = server.accept_socket(stream.as_raw_fd()).unwrap();

	let msg = "hello from server".to_string().into_bytes();
	conn.write(&msg).unwrap();

	let buf = conn.read(1024).unwrap();
	println!("server got: {}", std::str::from_utf8(buf.as_slice()));
}
