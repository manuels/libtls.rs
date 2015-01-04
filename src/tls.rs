#![allow(dead_code)]

extern crate libc;

use bindings;
use std;

use std::c_str::ToCStr;
use std::sync::{Once, ONCE_INIT};

use std::io::{IoResult,IoError,IoErrorKind};

static INIT: Once = ONCE_INIT;

pub fn tls_init() {
	INIT.call_once(|| {
		unsafe { assert!(bindings::tls_init() == 0) }
	});
}

pub struct TLSConfig {
	ptr: *mut bindings::tls_config
}

impl Drop for TLSConfig {
	fn drop(&mut self) {
		unsafe { bindings::tls_config_free(self.ptr) }
	}
}

impl TLSConfig {
	pub fn new() -> Result<Self, ()> {
		let ptr = unsafe { bindings::tls_config_new() };

		if ptr.is_null() {
			Err(())
		}
		else {
			Ok(TLSConfig { ptr: ptr })
		}
	}

	fn set_string(&self, func: unsafe extern fn(*mut bindings::tls_config, *const i8) -> i32,
			string: &str) -> Result<(),()>
	{
		let res = string.with_c_str(|cstr|
			unsafe { func(self.ptr, cstr) }
		);
		if res == 0 {
			Ok(())
		}
		else {
			Err(())
		}
	}

	pub fn set_ca_file(&self, ca_file: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_ca_file, ca_file)
	}

	pub fn set_ca_path(&self, ca_path: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_ca_path, ca_path)
	}

	pub fn set_cert_file(&self, ca_path: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_cert_file, ca_path)
	}

	pub fn set_cert_mem(&self, cert: *const libc::c_int, len: libc::c_int)
			-> Result<(),()>
	{
		if cert.is_null() {
			return Err(())
		}

		let res = unsafe { bindings::tls_config_set_cert_mem(self.ptr, cert, len) };
		if res == 0 {
			Ok(())
		}
		else {
			Err(())
		}
	}

	pub fn set_ciphers(&self, ciphers: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_ciphers, ciphers)
	}

	pub fn set_ecdhcurve(&self, curve_name: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_ecdhcurve, curve_name)
	}

	pub fn set_key_file(&self, key_file: &str) -> Result<(),()> {
		self.set_string(bindings::tls_config_set_key_file, key_file)
	}

	pub fn set_key_mem(&self, key: *const libc::c_int, len: libc::c_int)
			-> Result<(),()>
	{
		if key.is_null() {
			return Err(())
		}

		let res = unsafe { bindings::tls_config_set_key_mem(self.ptr, key, len) };
		if res == 0 {
			Ok(())
		}
		else {
			Err(())
		}
	}

	pub fn set_protocols(&self, protocols: libc::c_int) {
		unsafe { bindings::tls_config_set_protocols(self.ptr, protocols) }
	}


	pub fn set_verify_depth(&self, verify_depth: libc::c_int) {
		unsafe { bindings::tls_config_set_verify_depth(self.ptr, verify_depth) }
	}

	pub fn clear_keys(&self) {
		unsafe { bindings::tls_config_clear_keys(self.ptr) }
	}

	pub fn insecure_noverifyhost(&self) {
		unsafe { bindings::tls_config_insecure_noverifyhost(self.ptr) }
	}

	pub fn insecure_noverifycert(&self) {
		unsafe { bindings::tls_config_insecure_noverifycert(self.ptr) }
	}

	pub fn verify(&self) {
		unsafe { bindings::tls_config_verify(self.ptr) }
	}
}


pub struct TLS {
	ptr: *mut bindings::tls
}

impl Drop for TLS {
	fn drop(&mut self) {
		unsafe { bindings::tls_free(self.ptr) }
	}
}

impl TLS {
	pub fn client() -> Result<TLS,()> {
		let ptr = unsafe { bindings::tls_client() };
		if ptr.is_null() {
			Err(())
		} else {
			Ok(TLS { ptr: ptr })
		}
	}

	pub fn server() -> Result<TLS,()> {
		let ptr = unsafe { bindings::tls_server() };
		if ptr.is_null() {
			Err(())
		} else {
			Ok(TLS { ptr: ptr })
		}
	}

	pub fn configure(&self, config: &TLSConfig) -> Result<(),&'static str> {
		let res = unsafe { bindings::tls_configure(self.ptr, config.ptr) };

		if res == 0 {
			Ok(())
		}
		else {
			Err(self.get_error())
		}
	}

	fn get_error(&self) -> &'static str {
		unsafe {
			let s = bindings::tls_error(self.ptr);
			std::str::from_c_str(s)
		}
	}

	pub fn reset(&self) {
		unsafe { bindings::tls_reset(self.ptr) }
	}

	pub fn accept_socket(&self, socket: libc::c_int) -> Result<TLS,&'static str> {
		let mut ptr = 0 as *mut bindings::tls;
		let res = unsafe { bindings::tls_accept_socket(self.ptr, &mut ptr, socket) };

		if res != 0 || ptr.is_null() {
			Err(self.get_error())
		}
		else {
			Ok(TLS { ptr:ptr })
		}
	}

	pub fn connect(&self, host: &str, port: &str) -> Result<(), &'static str> {
		host.with_c_str(|host_ptr| {
			port.with_c_str(|port_ptr| {
				let res = unsafe { bindings::tls_connect(self.ptr, host_ptr, port_ptr) };

				if res == 0 {
					Ok(())
				} else {
					Err(self.get_error())
				}
			})
		})
	}

	pub fn connect_fds(&self, fd_read: libc::c_int, fd_write: libc::c_int, hostname: &str)
			-> Result<(), &'static str>
	{
		hostname.with_c_str(|host| {
			let res = unsafe { bindings::tls_connect_fds(self.ptr, fd_read, fd_write, host) };

			if res == 0 {
				Ok(())
			} else {
				Err(self.get_error())
			}
		})
	}

	pub fn connect_socket(&self, sock: libc::c_int, hostname: &str) -> Result<(), &'static str> {
		hostname.with_c_str(|host| {
			let res = unsafe { bindings::tls_connect_socket(self.ptr, sock, host) };

			if res == 0 {
				Ok(())
			} else {
				Err(self.get_error())
			}
		})
	}
	pub fn close(&self) -> Result<(), &'static str> {
		let res = unsafe { bindings::tls_close(self.ptr) };

		if res == 0 {
			Ok(())
		} else {
			Err(self.get_error())
		}
	}
}

impl Reader for TLS {
	fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
		let mut outlen = 0 as libc::size_t;

		let res = unsafe {
			bindings::tls_read(self.ptr, buf.as_mut_ptr() as *mut libc::c_void,
				buf.len() as libc::c_int, &mut outlen)
		};
		
		match res {
			0 => {
				Ok(outlen as uint)
			},
			bindings::TLS_READ_AGAIN => Ok(0),
			bindings::TLS_WRITE_AGAIN => Ok(0),
			6 /*SSL_ERROR_ZERO_RETURN*/ => Err(IoError {
				kind: IoErrorKind::EndOfFile,
				desc: self.get_error(),
				detail: None,
			}),
			_ => Err(IoError {
				kind: IoErrorKind::OtherIoError,
				desc: self.get_error(),
				detail: None,
			}),
		}
	}
}

impl Writer for TLS {
	fn write(&mut self, buf: &[u8]) -> IoResult<()> {
		let mut outlen = 0 as libc::size_t;

		let res = unsafe {
			bindings::tls_write(self.ptr, buf.as_ptr() as *const libc::c_void,
				buf.len() as i32, &mut outlen)
		};
		
		match res {
			0 => Ok(()),
			bindings::TLS_READ_AGAIN => Err(IoError {
				kind: IoErrorKind::EndOfFile,
				desc: "READ_AGAIN",
				detail: None,
			}),
			bindings::TLS_WRITE_AGAIN => Err(IoError {
				kind: IoErrorKind::EndOfFile,
				desc: "WRITE_AGAIN",
				detail: None,
			}),
			_ => Err(IoError {
				kind: IoErrorKind::OtherIoError,
				desc: self.get_error(),
				detail: None,
			}),
		}
	}
}