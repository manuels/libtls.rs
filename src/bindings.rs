extern crate libc;

/*
int tls_init()
*/
#[link(name="tls")]
#[link(name="crypto")]
#[link(name="ssl")]
extern "C" {
	pub fn tls_init() -> libc::c_int;
}


/*
const char * tls_error()
	(struct tls *) ctx [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_error(ctx: *mut tls) -> *const libc::c_char;
}


/*
struct tls_config * tls_config_new() [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_new() -> *mut tls_config;
}


/*
void tls_config_free()
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_free(config: *mut tls_config);
}


/*
int tls_config_set_ca_file()
	(struct tls_config *) config [struct tls_config *]
	(const char *) ca_file
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_ca_file(config: *mut tls_config, ca_file: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_ca_path()
	(struct tls_config *) config [struct tls_config *]
	(const char *) ca_path
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_ca_path(config: *mut tls_config, ca_path: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_cert_file()
	(struct tls_config *) config [struct tls_config *]
	(const char *) cert_file
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_cert_file(config: *mut tls_config, cert_file: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_cert_mem()
	(struct tls_config *) config [struct tls_config *]
	(const int *) cert
	(int) len
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_cert_mem(config: *mut tls_config, cert: *const libc::c_int, len: libc::c_int) -> libc::c_int;
}


/*
int tls_config_set_ciphers()
	(struct tls_config *) config [struct tls_config *]
	(const char *) ciphers
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_ciphers(config: *mut tls_config, ciphers: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_ecdhcurve()
	(struct tls_config *) config [struct tls_config *]
	(const char *) name
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_ecdhcurve(config: *mut tls_config, name: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_key_file()
	(struct tls_config *) config [struct tls_config *]
	(const char *) key_file
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_key_file(config: *mut tls_config, key_file: *const libc::c_char) -> libc::c_int;
}


/*
int tls_config_set_key_mem()
	(struct tls_config *) config [struct tls_config *]
	(const int *) key
	(int) len
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_key_mem(config: *mut tls_config, key: *const libc::c_int, len: libc::c_int) -> libc::c_int;
}


/*
void tls_config_set_protocols()
	(struct tls_config *) config [struct tls_config *]
	(int) protocols
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_protocols(config: *mut tls_config, protocols: libc::c_int);
}


/*
void tls_config_set_verify_depth()
	(struct tls_config *) config [struct tls_config *]
	(int) verify_depth
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_set_verify_depth(config: *mut tls_config, verify_depth: libc::c_int);
}


/*
void tls_config_clear_keys()
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_clear_keys(config: *mut tls_config);
}


/*
void tls_config_insecure_noverifyhost()
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_insecure_noverifyhost(config: *mut tls_config);
}


/*
void tls_config_insecure_noverifycert()
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_insecure_noverifycert(config: *mut tls_config);
}


/*
void tls_config_verify()
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_config_verify(config: *mut tls_config);
}


/*
struct tls * tls_client() [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_client() -> *mut tls;
}


/*
struct tls * tls_server() [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_server() -> *mut tls;
}


/*
int tls_configure()
	(struct tls *) ctx [struct tls *]
	(struct tls_config *) config [struct tls_config *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_configure(ctx: *mut tls, config: *mut tls_config) -> libc::c_int;
}


/*
void tls_reset()
	(struct tls *) ctx [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_reset(ctx: *mut tls);
}


/*
void tls_free()
	(struct tls *) ctx [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_free(ctx: *mut tls);
}


/*
int tls_accept_socket()
	(struct tls *) ctx [struct tls *]
	(struct tls **) cctx [struct tls **]
	(int) socket
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_accept_socket(ctx: *mut tls, cctx: *mut *mut tls, socket: libc::c_int) -> libc::c_int;
}


/*
int tls_connect()
	(struct tls *) ctx [struct tls *]
	(const char *) host
	(const char *) port
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_connect(ctx: *mut tls, host: *const libc::c_char, port: *const libc::c_char) -> libc::c_int;
}


/*
int tls_connect_fds()
	(struct tls *) ctx [struct tls *]
	(int) fd_read
	(int) fd_write
	(const char *) hostname
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_connect_fds(ctx: *mut tls, fd_read: libc::c_int, fd_write: libc::c_int, hostname: *const libc::c_char) -> libc::c_int;
}


/*
int tls_connect_socket()
	(struct tls *) ctx [struct tls *]
	(int) s
	(const char *) hostname
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_connect_socket(ctx: *mut tls, s: libc::c_int, hostname: *const libc::c_char) -> libc::c_int;
}


/*
int tls_read()
	(struct tls *) ctx [struct tls *]
	(void *) buf
	(int) buflen
	(size_t *) outlen
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_read(ctx: *mut tls, buf: *mut libc::c_void, buflen: libc::c_int, outlen: *mut libc::size_t) -> libc::c_int;
}


/*
int tls_write()
	(struct tls *) ctx [struct tls *]
	(const void *) buf
	(int) buflen
	(size_t *) outlen
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_write(ctx: *mut tls, buf: *const libc::c_void, buflen: libc::c_int, outlen: *mut libc::size_t) -> libc::c_int;
}


/*
int tls_close()
	(struct tls *) ctx [struct tls *]
*/
#[link(name="tls")]
extern "C" {
	pub fn tls_close(ctx: *mut tls) -> libc::c_int;
}


/*
struct tls
*/
#[repr(C)]
pub struct tls;

/*
struct tls_config
*/
#[repr(C)]
pub struct tls_config;

/* HEADER_TLS_H # */

/* TLS_API 20141031 # */
pub const TLS_API: i32 = 20141031;

/* TLS_PROTOCOL_TLSv1_0 ( 1 << 1 ) # */

/* TLS_PROTOCOL_TLSv1_1 ( 1 << 2 ) # */

/* TLS_PROTOCOL_TLSv1_2 ( 1 << 3 ) # */

/* TLS_PROTOCOL_TLSv1 ( TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2 ) # */

/* TLS_PROTOCOLS_DEFAULT TLS_PROTOCOL_TLSv1 # */

/* TLS_READ_AGAIN - 2 # */
pub const TLS_READ_AGAIN: i32 = -2;

/* TLS_WRITE_AGAIN - 3 struct */
pub const TLS_WRITE_AGAIN: i32 = -3;

