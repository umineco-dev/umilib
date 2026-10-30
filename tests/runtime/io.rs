use umilib::runtime::{
    AsyncRead, AsyncWrite, DuplexStream, Executor, IOError, IOErrorKind, Join, LocalExecutor, SocketAddress,
};

#[test]
fn duplex_streams_carry_bytes_both_ways_with_backpressure() {
    let executor = LocalExecutor::new();
    let (mut a, mut b) = DuplexStream::pair(16);
    let data: Vec<u8> = (0..10_000u32).map(|index| (index * 7) as u8).collect();
    let writer = {
        let data = data.clone();
        async move {
            let (result, _) = a.write_all(data).await;
            result.unwrap();
            a.shutdown().await.unwrap();
            a
        }
    };
    let reader = async move {
        let mut received = Vec::new();
        loop {
            let (result, buffer) = b.read(Vec::with_capacity(100)).await;
            let count = result.unwrap();
            if count == 0 {
                break;
            }
            assert!(count <= 16, "at most the capacity in flight");
            received.extend_from_slice(&buffer);
        }
        (received, b)
    };
    let (_a, (received, _b)) = executor.block_on(executor.spawn(Join::new(writer, reader))).unwrap();
    assert_eq!(received, data);
}

#[test]
fn duplex_streams_report_the_other_end_gone() {
    let executor = LocalExecutor::new();
    let (mut a, b) = DuplexStream::pair(4);
    drop(b);
    let (result, buffer) = executor.block_on(a.write(vec![1, 2, 3]));
    assert_eq!(result, Err(IOError::new(IOErrorKind::BrokenPipe)));
    assert_eq!(buffer, [1, 2, 3]);
    let (result, _) = executor.block_on(a.read(Vec::with_capacity(8)));
    assert_eq!(result, Ok(0));
}

#[test]
fn socket_addresses_print_as_usual() {
    let v4 = SocketAddress::V4 { address: [192, 0, 2, 1], port: 443 };
    assert_eq!(v4.to_string(), "192.0.2.1:443");
    assert_eq!(v4.port(), 443);
    let mut address = [0u8; 16];
    address[..2].copy_from_slice(&[0x20, 0x01]);
    address[15] = 1;
    let v6 = SocketAddress::V6 { address, port: 80, flow: 0, scope: 3 };
    assert_eq!(v6.to_string(), "[2001:0:0:0:0:0:0:1%3]:80");
}
