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

        let mut client = tls::TLS::client().unwrap();
        client.configure(&cfg).unwrap();

        client.connect("127.0.0.1", "4433").unwrap();

        client.write(b"hello from client").unwrap();

        let buf:Vec<u8> = client.read_exact(17).unwrap();
        assert_eq!(buf, b"hello from server".to_vec());
    }).detach();

    let stream = listener.accept().unwrap();
    let mut conn = server.accept_socket(stream.as_raw_fd()).unwrap();

    conn.write(b"hello from server").unwrap();

    let buf = conn.read_exact(17).unwrap();
    assert_eq!(buf, b"hello from client".to_vec());

    conn.close().unwrap();
