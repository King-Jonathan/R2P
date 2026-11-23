"""Chunking and reassembly tests."""

from r2p.protocol.chunking import (
    MessageAssembler,
    build_message_body,
    chunk_body,
    is_final_chunk,
)


def test_build_message_body():
    body = build_message_body("CALL", "hi")
    assert body.startswith("CALL")
    assert "¦" in body
    assert body.endswith("hi")


def test_chunk_and_reassemble():
    data = bytes(range(250))
    chunks = chunk_body(data, max_chunk=100)
    assert len(chunks) == 3
    assert len(chunks[-1]) < 100
    asm = MessageAssembler(max_chunk=100)
    assert asm.feed(b"msgid1", 0, chunks[0]) is None
    assert asm.feed(b"msgid1", 1, chunks[1]) is None
    done = asm.feed(b"msgid1", 2, chunks[2])
    assert done == data


def test_exact_multiple_gets_empty_final():
    data = bytes(range(200))
    chunks = chunk_body(data, max_chunk=100)
    assert len(chunks) == 3
    assert chunks[2] == b""
    asm = MessageAssembler(max_chunk=100)
    assert asm.feed(b"msgid2", 0, chunks[0]) is None
    assert asm.feed(b"msgid2", 1, chunks[1]) is None
    done = asm.feed(b"msgid2", 2, chunks[2])
    assert done == data


def test_single_chunk_final():
    assert is_final_chunk(50, 200)
    asm = MessageAssembler(max_chunk=200)
    done = asm.feed(b"idxxxx", 0, b"abc")
    assert done == b"abc"


def test_reassemble_final_chunk_first():
    data = bytes(range(250))
    chunks = chunk_body(data, max_chunk=100)
    asm = MessageAssembler(max_chunk=100)
    assert asm.feed(b"msgid3", 2, chunks[2]) is None
    assert asm.feed(b"msgid3", 0, chunks[0]) is None
    done = asm.feed(b"msgid3", 1, chunks[1])
    assert done == data
    assert asm.pending_count() == 0


def test_reassemble_reverse_order():
    data = bytes(range(200))
    chunks = chunk_body(data, max_chunk=100)
    assert chunks[2] == b""
    asm = MessageAssembler(max_chunk=100)
    assert asm.feed(b"msgid4", 2, chunks[2]) is None
    assert asm.feed(b"msgid4", 1, chunks[1]) is None
    done = asm.feed(b"msgid4", 0, chunks[0])
    assert done == data


def test_reassemble_final_then_only_missing_middle():
    data = bytes(range(250))
    chunks = chunk_body(data, max_chunk=100)
    asm = MessageAssembler(max_chunk=100)
    assert asm.feed(b"msgid5", 0, chunks[0]) is None
    assert asm.feed(b"msgid5", 2, chunks[2]) is None
    done = asm.feed(b"msgid5", 1, chunks[1])
    assert done == data
