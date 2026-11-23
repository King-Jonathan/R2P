"""UDP free-port bind for dual local clients."""

from r2p.transport.udp_socket import UdpTransport, _bind_free_port


def test_bind_free_port_preferred() -> None:
    sock, port = _bind_free_port(39100)
    try:
        assert 39100 <= port <= 39100 + 64
    finally:
        sock.close()


def test_second_client_gets_next_port() -> None:
    a = UdpTransport(39200)
    a.start()
    try:
        b = UdpTransport(39200)
        b.start()
        try:
            assert a.port == 39200
            assert b.port == 39201
            # both can send to each other on loopback
            received: list[bytes] = []

            def on_pkt(data: bytes, addr: tuple[str, int]) -> None:
                received.append(data)

            b.set_handler(on_pkt)
            a.sendto(b"hello-r2p", ("127.0.0.1", b.port))
            import time

            deadline = time.time() + 1.0
            while not received and time.time() < deadline:
                time.sleep(0.02)
            assert received and received[0] == b"hello-r2p"
        finally:
            b.stop()
    finally:
        a.stop()


def test_broadcast_ports_are_tight():
    t = UdpTransport(40100)
    t.start()
    try:
        ports = t.broadcast_ports()
        assert t.port in ports
        assert t.preferred_port in ports
        assert len(ports) <= 5
        assert max(ports) - min(ports) <= 3
    finally:
        t.stop()


def test_enqueue_send_delay_no_caller_sleep():
    import time

    a = UdpTransport(40200)
    b = UdpTransport(40201)
    received: list[tuple[bytes, float]] = []

    def on_pkt(data: bytes, addr: tuple[str, int]) -> None:
        received.append((data, time.monotonic()))

    b.set_handler(on_pkt)
    a.start()
    b.start()
    try:
        t0 = time.monotonic()
        a.enqueue_send(b"one", ("127.0.0.1", b.port), 0.0)
        a.enqueue_send(b"two", ("127.0.0.1", b.port), 0.05)
        elapsed = time.monotonic() - t0
        assert elapsed < 0.04
        deadline = time.monotonic() + 1.0
        while len(received) < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert [data for data, _ts in received] == [b"one", b"two"]
        assert received[1][1] - received[0][1] >= 0.035
    finally:
        a.stop()
        b.stop()
