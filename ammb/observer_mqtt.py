# ammb/observer_mqtt.py
"""
MeshCore observer MQTT packet codec.

Observer firmware (and compatible capture tools) publish LetsMesh-style JSON
on ``meshcore/{IATA}/{device_id}/packets``. Those frames are on-air MeshCore
packets: a header, path, and encrypted payload. They do not use AMMB's
``payload`` / ``payload_json`` schema.

This module:

* Detects observer PACKET/status/raw JSON
* Decrypts Public (and configured) channel group text
* Encodes Meshtastic text as flood GRP_TXT packets so MQTT clients that
  speak the observer schema can consume bridged traffic
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


LOGGER = logging.getLogger(__name__)

# Well-known MeshCore Public channel key (16 bytes).
# Hex: 8b3387e9c5cdea6ac9e5edbaa115cd72
# Base64: izOH6cXN6mrJ5e26oRXNcg==
PUBLIC_CHANNEL_KEY = bytes.fromhex("8b3387e9c5cdea6ac9e5edbaa115cd72")
PUBLIC_CHANNEL_NAME = "Public"

AES_BLOCK = 16
HMAC_KEY_SIZE = 32
CIPHER_MAC_SIZE = 2
MAX_HASH_SIZE = 8
MAX_PATH_SIZE = 64
MAX_PACKET_PAYLOAD = 184

ROUTE_FLOOD = 0x01
PAYLOAD_TYPE_TXT_MSG = 0x02
PAYLOAD_TYPE_GRP_TXT = 0x05
PAYLOAD_VER_1 = 0x00

PAYLOAD_TYPE_NAMES = {
    0: "REQ",
    1: "RESPONSE",
    2: "TXT_MSG",
    3: "ACK",
    4: "ADVERT",
    5: "GRP_TXT",
    6: "GRP_DATA",
    7: "ANON_REQ",
    8: "PATH",
    9: "TRACE",
    10: "MULTIPART",
    11: "CONTROL",
    15: "RAW_CUSTOM",
}

ROUTE_LETTERS = {0: "T", 1: "F", 2: "D", 3: "U"}

_SENDER_SPLIT = re.compile(r"^([^:\[\]]{1,48}): (.*)$", re.DOTALL)


class SeenHashCache:
    """Bounded LRU of recently seen observer packet hashes."""

    def __init__(self, max_size: int = 512):
        self._max_size = max(1, max_size)
        self._items: OrderedDict[str, None] = OrderedDict()

    def seen(self, packet_hash: str) -> bool:
        key = packet_hash.strip().upper()
        if not key:
            return False
        if key in self._items:
            self._items.move_to_end(key)
            return True
        self._items[key] = None
        if len(self._items) > self._max_size:
            self._items.popitem(last=False)
        return False


@dataclass(frozen=True)
class ChannelKey:
    """A MeshCore group-channel secret and its display name."""

    name: str
    secret: bytes

    @property
    def channel_hash(self) -> int:
        return hashlib.sha256(self.secret).digest()[0]


@dataclass
class ParsedPacket:
    """Decoded MeshCore on-air frame (header + path + payload)."""

    raw: bytes
    header: int
    route_type: int
    payload_type: int
    payload_version: int
    path: bytes
    hop_count: int
    hash_size: int
    payload: bytes

    @property
    def packet_hash(self) -> str:
        return calculate_packet_hash(self.payload_type, self.payload)


@dataclass
class GroupText:
    """Decrypted MeshCore group-channel text."""

    sender: Optional[str]
    text: str
    timestamp: int
    channel_name: str
    channel_hash: int


def hashtag_channel_key(name: str) -> bytes:
    """Derive the 16-byte secret for a ``#name`` MeshCore room."""
    cleaned = name.strip().lstrip("#")
    return hashlib.sha256(("#" + cleaned).encode("utf-8")).digest()[:16]


def _parse_hex_secret(value: str) -> bytes:
    hex_str = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(hex_str) < 32:
        raise ValueError("channel key must be at least 16 bytes hex")
    return bytes.fromhex(hex_str[:32])


def parse_channel_keys(
    primary: Optional[str] = None,
    extra: str = "",
    include_public: bool = True,
) -> List[ChannelKey]:
    """Build the decrypt/encrypt key list from config strings."""
    keys: List[ChannelKey] = []
    seen: set[bytes] = set()

    def add(name: str, secret: bytes) -> None:
        secret16 = secret[:16]
        if len(secret16) != 16 or secret16 in seen:
            return
        seen.add(secret16)
        keys.append(ChannelKey(name=name, secret=secret16))

    if include_public:
        add(PUBLIC_CHANNEL_NAME, PUBLIC_CHANNEL_KEY)

    if primary:
        token = primary.strip()
        if token:
            if token.startswith("#"):
                add(token, hashtag_channel_key(token))
            else:
                add("configured", _parse_hex_secret(token))

    for part in (extra or "").split(","):
        token = part.strip()
        if not token:
            continue
        if token.startswith("#"):
            add(token, hashtag_channel_key(token))
            continue
        if "=" in token:
            name, raw_key = token.split("=", 1)
            add(name.strip() or "channel", _parse_hex_secret(raw_key))
            continue
        add("channel", _parse_hex_secret(token))

    return keys


def _hmac_key(secret16: bytes) -> bytes:
    # MeshCore HMAC uses PUB_KEY_SIZE (32) bytes. Channel secrets are 16 bytes
    # stored in a 32-byte buffer padded with zeros.
    return secret16[:16] + b"\x00" * 16


def _aes_ecb(secret16: bytes, data: bytes, *, encrypt: bool) -> bytes:
    if len(data) % AES_BLOCK != 0:
        raise ValueError("AES-ECB data must be a multiple of 16 bytes")
    cipher = Cipher(algorithms.AES(secret16[:16]), modes.ECB())
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


def encrypt_then_mac(secret16: bytes, plaintext: bytes) -> bytes:
    """MeshCore encrypt-then-MAC: 2-byte HMAC + AES-128-ECB ciphertext."""
    padded = plaintext
    remainder = len(padded) % AES_BLOCK
    if remainder:
        padded = padded + b"\x00" * (AES_BLOCK - remainder)
    ciphertext = _aes_ecb(secret16, padded, encrypt=True)
    mac = hmac.new(_hmac_key(secret16), ciphertext, hashlib.sha256).digest()
    return mac[:CIPHER_MAC_SIZE] + ciphertext


def mac_then_decrypt(secret16: bytes, blob: bytes) -> Optional[bytes]:
    """Verify the 2-byte HMAC and AES-decrypt. None if the MAC mismatches."""
    if len(blob) <= CIPHER_MAC_SIZE:
        return None
    mac, ciphertext = blob[:CIPHER_MAC_SIZE], blob[CIPHER_MAC_SIZE:]
    if len(ciphertext) % AES_BLOCK != 0:
        return None
    expected = hmac.new(
        _hmac_key(secret16), ciphertext, hashlib.sha256
    ).digest()[:CIPHER_MAC_SIZE]
    if not hmac.compare_digest(mac, expected):
        return None
    return _aes_ecb(secret16, ciphertext, encrypt=False)


def calculate_packet_hash(payload_type: int, payload: bytes) -> str:
    """SHA-256(payload_type || payload), truncated to 8 bytes, upper hex."""
    digest = hashlib.sha256(bytes([payload_type & 0xFF]) + payload).digest()
    return digest[:MAX_HASH_SIZE].hex().upper()


def parse_raw_packet(raw_hex: str) -> Optional[ParsedPacket]:
    """Parse on-air MeshCore bytes from an observer ``raw`` hex string."""
    try:
        raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw_hex or ""))
    except ValueError:
        return None
    if len(raw) < 3:
        return None

    header = raw[0]
    route_type = header & 0x03
    payload_type = (header >> 2) & 0x0F
    payload_version = (header >> 6) & 0x03
    offset = 1
    if route_type in (0x00, 0x03):
        offset += 4
        if len(raw) < offset + 2:
            return None

    path_len_field = raw[offset]
    offset += 1
    hop_count = path_len_field & 0x3F
    hash_size = ((path_len_field >> 6) & 0x03) + 1
    if hash_size == 4:
        return None
    path_bytes = hop_count * hash_size
    if path_bytes > MAX_PATH_SIZE or offset + path_bytes > len(raw):
        return None
    path = raw[offset : offset + path_bytes]
    offset += path_bytes
    payload = raw[offset:]
    if not payload or len(payload) > MAX_PACKET_PAYLOAD:
        return None
    return ParsedPacket(
        raw=raw,
        header=header,
        route_type=route_type,
        payload_type=payload_type,
        payload_version=payload_version,
        path=path,
        hop_count=hop_count,
        hash_size=hash_size,
        payload=payload,
    )


def _strip_nul(text: str) -> str:
    return text.split("\x00", 1)[0]


def decrypt_group_text(
    payload: bytes,
    keys: Sequence[ChannelKey],
) -> Optional[GroupText]:
    """Decrypt a GRP_TXT payload with the first matching channel key."""
    if len(payload) < 1 + CIPHER_MAC_SIZE + AES_BLOCK:
        return None
    channel_hash = payload[0]
    blob = payload[1:]
    for key in keys:
        if key.channel_hash != channel_hash:
            continue
        plaintext = mac_then_decrypt(key.secret, blob)
        if plaintext is None or len(plaintext) < 5:
            continue
        timestamp = int.from_bytes(plaintext[0:4], "little", signed=False)
        message = _strip_nul(plaintext[5:].decode("utf-8", errors="replace"))
        sender = None
        text = message
        match = _SENDER_SPLIT.match(message)
        if match:
            sender, text = match.group(1), match.group(2)
        return GroupText(
            sender=sender,
            text=text,
            timestamp=timestamp,
            channel_name=key.name,
            channel_hash=channel_hash,
        )
    return None


def encode_group_text_packet(
    text: str,
    sender_name: str,
    channel_key: ChannelKey,
    *,
    timestamp: Optional[int] = None,
    origin: str = "AMMB",
    origin_id: str = "",
) -> Dict[str, Any]:
    """Build observer PACKET JSON for a flood GRP_TXT message."""
    ts = int(timestamp if timestamp is not None else time.time())
    body = text if not sender_name else f"{sender_name}: {text}"
    plaintext = ts.to_bytes(4, "little") + b"\x00" + body.encode("utf-8")
    mac_and_ct = encrypt_then_mac(channel_key.secret, plaintext)
    payload = bytes([channel_key.channel_hash]) + mac_and_ct
    header = (
        ((PAYLOAD_VER_1 & 0x03) << 6)
        | ((PAYLOAD_TYPE_GRP_TXT & 0x0F) << 2)
        | (ROUTE_FLOOD & 0x03)
    )
    raw = bytes([header, 0x00]) + payload
    now = datetime.now(timezone.utc)
    packet_hash = calculate_packet_hash(PAYLOAD_TYPE_GRP_TXT, payload)
    return {
        "timestamp": now.isoformat(),
        "hash": packet_hash,
        "origin": origin,
        "origin_id": origin_id,
        "type": "PACKET",
        "direction": "tx",
        "time": now.strftime("%H:%M:%S"),
        "date": now.strftime("%d/%m/%Y"),
        "len": str(len(raw)),
        "packet_type": str(PAYLOAD_TYPE_GRP_TXT),
        "route": "F",
        "payload_len": str(len(payload)),
        "raw": raw.hex().upper(),
    }


def topic_is_observer_control(topic: str) -> bool:
    """True for observer status/neighbors topics that are not text traffic."""
    lowered = (topic or "").rstrip("/").lower()
    return lowered.endswith("/status") or lowered.endswith("/neighbors")


def is_observer_status(data: Dict[str, Any]) -> bool:
    status = data.get("status")
    return isinstance(status, str) and status.lower() in {"online", "offline"}


def is_observer_packet(data: Dict[str, Any]) -> bool:
    """True when JSON looks like a MeshCore observer packet or raw frame."""
    if not isinstance(data, dict):
        return False
    msg_type = str(data.get("type") or "").upper()
    if msg_type == "PACKET":
        return bool(data.get("raw") or data.get("decoded"))
    if msg_type == "RAW":
        return bool(data.get("data") or data.get("raw"))
    if data.get("raw") and data.get("packet_type") is not None:
        return True
    return False


def _decoded_group_text(decoded: Any) -> Optional[str]:
    if not isinstance(decoded, dict):
        return None
    if decoded.get("decrypted") is False:
        return None
    kind = str(decoded.get("kind") or "").upper()
    if kind and kind not in {"GRP_TXT", "GROUP_TEXT", "TXT_MSG", "TEXT"}:
        return None
    text = decoded.get("text") or decoded.get("message")
    if not isinstance(text, str) or not text.strip():
        return None
    sender = decoded.get("sender")
    if isinstance(sender, str) and sender.strip():
        if text.startswith(sender.strip() + ":"):
            return text
        return f"{sender.strip()}: {text}"
    return text


def observer_packet_to_bridge_message(
    data: Dict[str, Any],
    keys: Sequence[ChannelKey],
    *,
    default_destination: str = "^all",
    default_channel_index: int = 0,
) -> Optional[Dict[str, Any]]:
    """
    Convert observer PACKET JSON into AMMB's external-message dict.

    Returns None when the frame is not bridged text (adverts, encrypted DMs,
    undecryptable group text, control).
    """
    decoded_text = _decoded_group_text(data.get("decoded"))
    raw_hex = data.get("raw") or data.get("data") or ""
    parsed = parse_raw_packet(str(raw_hex)) if raw_hex else None

    packet_type = None
    if parsed is not None:
        packet_type = parsed.payload_type
    elif data.get("packet_type") is not None:
        try:
            packet_type = int(str(data.get("packet_type")).strip())
        except (TypeError, ValueError):
            packet_type = None

    text_payload: Optional[str] = None
    sender: Optional[str] = None

    if decoded_text:
        text_payload = decoded_text
        decoded = data.get("decoded")
        if isinstance(decoded, dict):
            decoded_sender = decoded.get("sender")
            if isinstance(decoded_sender, str) and decoded_sender.strip():
                sender = decoded_sender.strip()
    elif parsed is not None and parsed.payload_type == PAYLOAD_TYPE_GRP_TXT:
        group = decrypt_group_text(parsed.payload, keys)
        if group is None:
            LOGGER.debug(
                "Observer GRP_TXT could not be decrypted (hash=%s)",
                data.get("hash"),
            )
            return None
        sender = group.sender
        text_payload = (
            f"{group.sender}: {group.text}" if group.sender else group.text
        )
    elif packet_type == PAYLOAD_TYPE_TXT_MSG:
        LOGGER.debug(
            "Ignoring observer TXT_MSG (direct messages stay encrypted)"
        )
        return None
    else:
        LOGGER.debug(
            "Ignoring observer packet type %s (hash=%s)",
            packet_type if packet_type is not None else data.get("packet_type"),
            data.get("hash"),
        )
        return None

    if not text_payload or not text_payload.strip():
        return None

    origin = data.get("origin")
    if sender is None and isinstance(origin, str) and origin.strip():
        if not text_payload.startswith(origin.strip() + ":"):
            text_payload = f"{origin.strip()}: {text_payload}"

    message: Dict[str, Any] = {
        "destination_meshtastic_id": default_destination,
        "payload": text_payload.strip(),
        "channel_index": default_channel_index,
        "want_ack": False,
        "observer_hash": str(data.get("hash") or ""),
        "observer_origin": origin,
        "observer_packet_type": packet_type,
    }
    if parsed is not None:
        message["observer_hash"] = parsed.packet_hash
    return message


def meshtastic_item_to_observer_packet(
    item: Dict[str, Any],
    channel_key: ChannelKey,
    *,
    origin: str,
    origin_id: str,
) -> Optional[Dict[str, Any]]:
    """Encode a Meshtastic-originated text item as observer PACKET JSON."""
    if item.get("type") not in (None, "meshtastic_message"):
        return None
    payload = item.get("payload")
    if not isinstance(payload, str) or not payload.strip():
        return None
    sender = item.get("sender_display_name") or item.get("sender_meshtastic_id")
    sender_name = sender.strip() if isinstance(sender, str) else ""
    ts = item.get("timestamp_rx")
    timestamp = int(ts) if isinstance(ts, (int, float)) else None
    return encode_group_text_packet(
        payload.strip(),
        sender_name,
        channel_key,
        timestamp=timestamp,
        origin=origin,
        origin_id=origin_id,
    )


def first_channel_key(keys: Iterable[ChannelKey]) -> Optional[ChannelKey]:
    for key in keys:
        return key
    return None
