"""Nostr event id/sig check and OK handling."""

import asyncio

from r2p.crypto.vibe import VibeKeys
from r2p.crypto.cipher import nostr_filter_tag
from r2p.protocol.packet import PROTOCOL_PIXEL
from r2p.discovery.nostr_backend import (
    KIND_EPHEMERAL,
    NostrDiscoveryBackend,
    build_event,
    verify_event,
)


def test_verify_event_accepts_own_build():
    v = VibeKeys("liberty", "7.074")
    b = NostrDiscoveryBackend(relays=[], vibe=v, protocol=PROTOCOL_PIXEL, get_presence=lambda: None)
    ev = build_event(b._priv, b._pub_hex, KIND_EPHEMERAL, [["t", "aa"]], "hi")
    assert verify_event(ev)


def test_verify_event_rejects_bad_sig():
    v = VibeKeys("liberty", "7.074")
    b = NostrDiscoveryBackend(relays=[], vibe=v, protocol=PROTOCOL_PIXEL, get_presence=lambda: None)
    ev = build_event(b._priv, b._pub_hex, KIND_EPHEMERAL, [["t", "aa"]], "hi")
    ev["sig"] = ("00" * 64)
    assert not verify_event(ev)


def test_ok_true_and_false_update_state():
    v = VibeKeys("liberty", "7.074")
    notes: list[str] = []
    b = NostrDiscoveryBackend(
        relays=[],
        vibe=v,
        protocol=PROTOCOL_PIXEL,
        get_presence=lambda: None,
        on_relay_status=notes.append,
    )
    b._handle_ok("wss://relay.example", ["OK", "abc", True, ""])
    assert b.last_ok["wss://relay.example"][0] is True
    assert notes[-1].startswith("nostr ok")
    b._handle_ok("wss://relay.example", ["OK", "abc", False, "blocked"])
    assert b.last_ok["wss://relay.example"] == (False, "blocked")
    assert "reject" in notes[-1]


def test_handle_message_drops_unsigned_event():
    v = VibeKeys("liberty", "7.074")
    seen: list[str] = []
    b = NostrDiscoveryBackend(
        relays=[],
        vibe=v,
        protocol=PROTOCOL_PIXEL,
        get_presence=lambda: None,
        on_presence=lambda text, protocol: seen.append(text),
    )
    fake = {
        "id": "00" * 32,
        "pubkey": "11" * 32,
        "created_at": 1,
        "kind": KIND_EPHEMERAL,
        "tags": [["t", nostr_filter_tag(v.refresh().current, PROTOCOL_PIXEL)]],
        "content": "deadbeef",
        "sig": "22" * 64,
    }
    import json

    asyncio.run(b._handle_message(json.dumps(["EVENT", "r2p", fake]), "wss://x"))
    assert seen == []


def test_nostr_start_stop_returns():
    v = VibeKeys("liberty", "7.074")
    b = NostrDiscoveryBackend(relays=[], vibe=v, protocol=PROTOCOL_PIXEL, get_presence=lambda: None)
    b.start()
    b.stop()


def test_nostr_tags_filter_rooms_protocols_and_adjacent_slots():
    import base64
    import json
    from unittest.mock import patch

    from r2p.crypto.cipher import endpoint_encrypt, expand_presence_key
    from r2p.crypto.vibe import vibe_key_for_slot
    from r2p.discovery.presence import encode_presence
    from r2p.protocol.packet import PROTOCOL_SPECTROGRAM

    presence = encode_presence(bytes.fromhex("aabbccddeeff0011"), [("198.51.100.20", 19302)])
    seen = []

    class Relay:
        async def send(self, raw):
            self.message = json.loads(raw)

    with patch("time.time", return_value=1_700_000_100):
        publisher = NostrDiscoveryBackend(
            relays=[], vibe=VibeKeys("liberty", "7.074"), protocol=PROTOCOL_PIXEL,
            get_presence=lambda: presence,
        )
        receiver = NostrDiscoveryBackend(
            relays=[], vibe=VibeKeys("liberty", "7.074"), protocol=PROTOCOL_PIXEL,
            get_presence=lambda: None, on_presence=lambda raw, protocol: seen.append((raw, protocol)),
        )
        relay = Relay()
        publisher._connections["relay"] = relay
        asyncio.run(publisher._publish_all())
        event = relay.message[1]
        requested = json.loads(receiver._req_message())[2]["#t"]
        assert len(requested) == 3
        assert event["tags"] == [["t", tag] for tag in requested]
        incoming = json.dumps(["EVENT", "r2p", event])
        asyncio.run(receiver._handle_message(incoming))
        assert seen == [(presence, PROTOCOL_PIXEL)]

        for channel, frequency, protocol in (
            ("other", "7.074", PROTOCOL_PIXEL),
            ("liberty", "14.074", PROTOCOL_PIXEL),
            ("liberty", "7.074", PROTOCOL_SPECTROGRAM),
        ):
            other = NostrDiscoveryBackend(
                relays=[], vibe=VibeKeys(channel, frequency), protocol=protocol,
                get_presence=lambda: None,
            )
            assert set(json.loads(other._req_message())[2]["#t"]).isdisjoint(requested)
            with patch("r2p.discovery.nostr_backend.verify_event", side_effect=AssertionError("wrong tag verified")):
                asyncio.run(other._handle_message(incoming))

        for tags in (None, [], [None], [["t"]], [["t", []]], [["t", "old-hash-tag"]]):
            malformed = dict(event, tags=tags)
            with patch("r2p.discovery.nostr_backend.verify_event", side_effect=AssertionError("wrong tag verified")):
                asyncio.run(receiver._handle_message(json.dumps(["EVENT", "r2p", malformed])))

        snap = publisher._vibe.snapshot()
        for key, pkey in ((snap.last, snap.presence_last), (snap.next, snap.presence_next)):
            event = build_event(
                publisher._priv, publisher._pub_hex, KIND_EPHEMERAL,
                [["t", nostr_filter_tag(key, PROTOCOL_PIXEL)]],
                base64.b64encode(endpoint_encrypt(pkey, presence)).decode("ascii"),
            )
            asyncio.run(receiver._handle_message(json.dumps(["EVENT", "r2p", event])))
        assert seen == [(presence, PROTOCOL_PIXEL)] * 3
        outside = vibe_key_for_slot("liberty", "7.074", snap.slot + 600)
        event = build_event(
            publisher._priv, publisher._pub_hex, KIND_EPHEMERAL,
            [["t", nostr_filter_tag(outside, PROTOCOL_PIXEL)]],
            base64.b64encode(endpoint_encrypt(expand_presence_key(outside), presence)).decode("ascii"),
        )
        with patch("r2p.discovery.nostr_backend.verify_event", side_effect=AssertionError("outside slot verified")):
            asyncio.run(receiver._handle_message(json.dumps(["EVENT", "r2p", event])))
        receiver.on_vibe_changed(PROTOCOL_SPECTROGRAM)
        assert set(json.loads(receiver._req_message())[2]["#t"]).isdisjoint(requested)


def test_nostr_refreshes_then_publishes_on_settings_and_five_minute_boundaries():
    import json
    from pathlib import Path
    from unittest.mock import patch

    from r2p.app_core import AppCore
    from r2p.config import Config
    from r2p.crypto.vibe import vibe_key_for_slot
    from r2p.discovery.presence import encode_presence
    from r2p.protocol.packet import PROTOCOL_SPECTROGRAM

    class Relay:
        def __init__(self):
            self.messages = []
            self.on_event = None

        async def send(self, raw):
            message = json.loads(raw)
            self.messages.append(message)
            if message[0] == "EVENT" and self.on_event:
                callback, self.on_event = self.on_event, None
                callback()

    hour = (1_700_000_000 // 3600) * 3600
    clock = [hour + 1]
    sample_presence = encode_presence(bytes.fromhex("aabbccddeeff0011"), [("198.51.100.20", 19302)])
    peer_presence = encode_presence(bytes.fromhex("aabbccddeeff0011"), [("198.51.100.21", 19302)])
    with patch("time.time", side_effect=lambda: clock[0]):
        core = AppCore(Config(
            nostr_relays=[], encodings_path=str(Path(__file__).resolve().parents[1] / "encodings.json"),
        ))
        backend = core._backends[0]
        backend._get_presence = lambda: sample_presence
        relay = Relay()
        backend._connections["relay"] = relay
        try:
            asyncio.run(backend._update_relays())
            with patch.object(backend, "_request_publish", side_effect=lambda: asyncio.run(backend._update_relays())):
                previous = set(relay.messages[-1][1]["tags"][i][1] for i in range(3))
                for change in (
                    lambda: core.set_frequency("14.074"),
                    lambda: core.set_channel_key("new-channel"),
                    lambda: core.set_message_mode("spectrogram"),
                ):
                    core.peers.add("198.51.100.21", 19302)
                    epoch_before = core._room_epoch
                    start = len(relay.messages)
                    change()
                    assert core._room_epoch == epoch_before + 1
                    messages = relay.messages[start:]
                    assert [message[0] for message in messages] == ["CLOSE", "REQ", "EVENT"]
                    tags = messages[1][2]["#t"]
                    assert previous.isdisjoint(tags)
                    assert messages[2][1]["tags"] == [["t", tag] for tag in tags]
                    assert core.peer_count() == 0
                    previous = set(tags)
                core._on_nostr_presence(peer_presence, PROTOCOL_PIXEL)
                assert core.peer_count() == 0
                count = len(relay.messages)
                core.set_message_mode("spectrogram")
                assert len(relay.messages) == count

                # Run the real timer loop just before, at, and after each boundary.
                boundaries = list(range(hour + 300, hour + 3601, 300))
                ticks = iter(t for boundary in boundaries for t in (boundary - 1, boundary, boundary + 1))

                def wait(_timeout):
                    try:
                        clock[0] = next(ticks)
                    except StopIteration:
                        return True
                    return False

                start = len(relay.messages)
                with patch.object(core._stop, "wait", side_effect=wait):
                    core._timer_loop()
                messages = relay.messages[start:]
                assert len(messages) == 3 * len(boundaries)
                for index, boundary in enumerate(boundaries):
                    close, request, publication = messages[index * 3:index * 3 + 3]
                    assert [close[0], request[0], publication[0]] == ["CLOSE", "REQ", "EVENT"]
                    assert publication[1]["created_at"] == boundary
                    expected = nostr_filter_tag(
                        vibe_key_for_slot("new-channel", "14.074", boundary), PROTOCOL_SPECTROGRAM,
                    )
                    assert expected in request[2]["#t"]
                    assert publication[1]["tags"] == [["t", tag] for tag in request[2]["#t"]]

            # A settings change during an awaited send must keep the new publish pending.
            with patch.object(backend, "_request_publish"):
                core.set_message_mode("pixel")
                relay.on_event = lambda: core.set_message_mode("spectrogram")
                asyncio.run(backend._update_relays())
                assert backend._force_publish and backend._need_resub
                asyncio.run(backend._update_relays())
                assert not backend._force_publish and not backend._need_resub
                assert relay.messages[-1][1]["tags"] == [["t", tag] for tag in json.loads(backend._req_message())[2]["#t"]]
        finally:
            core.stop()


def test_nostr_new_peer_gets_gossip_and_can_send_chat_back():
    import base64
    import json
    from contextlib import ExitStack
    from pathlib import Path
    from unittest.mock import patch

    from r2p.app_core import AppCore
    from r2p.config import Config
    from r2p.crypto.cipher import body_decrypt, endpoint_encrypt
    from r2p.discovery.presence import decode_presence
    from r2p.encoding.tables import codes_to_glyphs, encode_text
    from r2p.protocol.chunking import build_message_body
    from r2p.protocol.packet import PROTOCOL_DISCOVERY, packet_aad, unpack_packet

    encodings = str(Path(__file__).resolve().parents[1] / "encodings.json")
    a = AppCore(Config(encodings_path=encodings, nostr_relays=[]))
    b = AppCore(Config(encodings_path=encodings, nostr_relays=[]))
    addr_a = ("203.0.113.10", 19302)
    addr_b = ("198.51.100.20", 19302)
    try:
        with ExitStack() as stack:
            for core, addr in ((a, addr_a), (b, addr_b)):
                core._public_ip = addr[0]
                stack.enter_context(patch.object(core, "_our_endpoints", return_value=[addr]))
                stack.enter_context(patch.object(core, "_local_ips", return_value=set()))
            send_a = stack.enter_context(patch.object(a._udp, "enqueue_send"))
            send_b = stack.enter_context(patch.object(b._udp, "enqueue_send"))
            a.peers.add("192.0.2.30", 19302)
            backend_a = a._backends[0]
            backend_b = b._backends[0]

            def receive_presence(raw: bytes):
                snap = b.vibe.refresh()
                content = base64.b64encode(endpoint_encrypt(snap.presence_current, raw)).decode("ascii")
                event = build_event(
                    backend_b._priv,
                    backend_b._pub_hex,
                    KIND_EPHEMERAL,
                    [["t", snap.nostr_tags(b.message_protocol)[1]]],
                    content,
                )
                asyncio.run(backend_a._handle_message(json.dumps(["EVENT", "r2p", event])))

            # Ignore invalid presence and our own instance.
            receive_presence(b"invalid")
            receive_presence(a.get_presence_bytes())
            assert send_a.call_count == 0

            presence_b = b.get_presence_bytes()
            receive_presence(presence_b)
            assert addr_b in a.peers.all()
            assert send_a.call_count == 2
            first, second = [call.args for call in send_a.call_args_list]
            assert first[1:] == (addr_b, 0.0)
            assert second[1] == addr_b
            assert 0.005 <= second[2] <= 0.020
            packet = unpack_packet(first[0])
            duplicate = unpack_packet(second[0])
            assert packet is not None and duplicate == packet
            assert first[0] != second[0]
            assert packet.protocol == PROTOCOL_DISCOVERY
            plain = body_decrypt(
                b.vibe.refresh().body_current,
                packet.message_id,
                packet.chunk_id,
                packet.body,
                packet.protocol,
                packet_aad(packet),
            )
            assert plain is not None
            assert decode_presence(plain) == (a._instance_id, [addr_a])

            # Repeated relay events must not send more gossip.
            receive_presence(presence_b)
            assert send_a.call_count == 2

            # UDP gossip adds the NAT return address without a reply or a chat log entry.
            nat_addr_a = (addr_a[0], 41234)
            b._on_udp(first[0], nat_addr_a)
            b._on_udp(second[0], nat_addr_a)
            assert b.peers.all() == [nat_addr_a]
            assert send_b.call_count == 0
            assert b.log_entries() == []

            b.send_chat("hello")
            assert send_b.call_count == 2
            for call in send_b.call_args_list:
                raw, target, _delay = call.args
                assert target == nat_addr_a
                a._on_udp(raw, addr_b)
            entries = a.log_entries()
            assert len(entries) == 1 and not entries[0].local
            expected = encode_text(a.tables, build_message_body(b.callsign, "hello"))
            assert entries[0].content == codes_to_glyphs(a.tables, expected)

            # WSL relay packets fall back to the advertised presence address.
            b.peers.clear()
            b.dedup = type(b.dedup)(ttl_seconds=600.0)
            b._wsl_relay.relay_hosts = {"172.24.0.1"}
            b._on_udp(first[0], ("172.24.0.1", 55555))
            assert b.peers.all() == [addr_a]
    finally:
        a.stop()
        b.stop()
