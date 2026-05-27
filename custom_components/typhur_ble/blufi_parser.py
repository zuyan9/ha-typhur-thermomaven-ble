import asyncio
import struct
import hashlib
import os
import json
import zlib
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_LOGGER = logging.getLogger(__name__)

DH_P = "0x00c7391ab1a6575775fba187f58ccfe9eaee0f41ab1e9ef57be14bd4b5e28a9be1c54e0b0cf7bc66b3bcfbbd7ab013a7a92fb47dc6a0ca97cb4bfbf4b7c3d2f9b2d87e1451f28b3e839e55a73e5bf02bfa40411ed0262fc7df7b0b694901f4c71e9a2f6412170ba37af9391ab0b12bcbe4ef43d1a49a941cd99e2a8626e2ebaf23"

class BlufiCrypto:
    def __init__(self):
        self.p = int(DH_P, 0)
        self.g = 5
        self.privKey = int.from_bytes(os.urandom(128), "big")
        self.pubKey = pow(self.g, self.privKey, self.p)

    def derive_shared_key(self, peer_pub_bytes):
        y_peer = int.from_bytes(peer_pub_bytes, "big")
        shared_int = pow(y_peer, self.privKey, self.p)
        shared_bytes = shared_int.to_bytes(128, 'big')
        digest = hashlib.md5()
        digest.update(shared_bytes)
        return digest.digest()

class AsyncBlufiClient:
    def __init__(self, client, address, callback=None):
        self.client = client
        self.address = address
        self.callback = callback
        self.crypto = BlufiCrypto()
        self.aes_key = None
        self.rx_buf = bytearray()
        self.pub_key_buf = bytearray()
        self.write_char = "0000ff01-0000-1000-8000-00805f9b34fb"
        self.notify_char = "0000ff02-0000-1000-8000-00805f9b34fb"
        self.seq = 0
        self.expected_len = 0
        self._security_task = None
        self.is_wt11 = self.address.upper().startswith("98:A3")
        self.has_received_peer_key = False
        
    async def setup(self):
        try:
            if hasattr(self.client, 'get_services'):
                await self.client.get_services()
            elif not self.client.services:
                _LOGGER.error(f"[{self.address}] Client services is empty")
            await self.client.start_notify(self.notify_char, self._on_notify)
            _LOGGER.error(f"[{self.address}] Successfully started notify")

            if self.is_wt11:
                self._security_task = asyncio.create_task(self._negotiate_security())
            else:
                self._security_task = asyncio.create_task(self._negotiate_security())
        except Exception as e:
            _LOGGER.error(f"[{self.address}] Setup failed: {e}")
            
    def _generate_iv(self, seq):
        iv = bytearray(16)
        iv[0] = seq
        return bytes(iv)


    async def _post_encrypted(self, type_val, frame_ctrl, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import struct
        
        # Standard Blufi: calculate CRC16 of plaintext and append it
        def crc16_ccitt_false(data):
            crc = 0
            for b in data:
                crc = crc ^ (b << 8)
                for _ in range(8):
                    if crc & 0x8000:
                        crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                    else:
                        crc = (crc << 1) & 0xFFFF
            return crc
            
        # We bypass Blufi-level checksum because Typhur payloads have internal CRC16 anyway.
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(self._generate_iv(self.seq)), backend=default_backend())
        encryptor = cipher.encryptor()
        enc_data = bytearray(encryptor.update(bytes(data)) + encryptor.finalize())
        
        # Set Encryption (0x08) ONLY
        await self._post(type_val, frame_ctrl | 0x08, enc_data)

    async def _post(self, type_val, frame_ctrl, data):
        # Throttle writes slightly to avoid overwhelming Pi HCI stack
        await asyncio.sleep(0.1)
        data = data or bytearray()
        
        # Determine the maximum payload size based on MTU if available.
        # Blufi uses MTU - 3 for max GATT payload. But we limit to 500 as a safe upper bound.
        client_mtu = getattr(self.client, 'mtu_size', 500)
        max_payload = max(20, client_mtu - 10) # 490 if MTU=500
        
        # Cap max_payload to 255 because Blufi payload length in header is an 8-bit integer!
        # Wait, if total_len is > 255, Blufi REQUIRES fragmentation?
        # Actually, Blufi header has a 1-byte length field (`<BBBB`), so max unfragmented length is 255 bytes!
        max_payload = min(max_payload, 250)

        total_len = len(data)
        
        if total_len <= max_payload:
            header = struct.pack("<BBBB", type_val, frame_ctrl, self.seq, total_len)
            self.seq = (self.seq + 1) % 256
            try:
                await self.client.write_gatt_char(self.write_char, header + data, response=True)
            except Exception as e:
                _LOGGER.error(f"[{self.address}] Failed to write GATT char: {e}")
        else:
            offset = 0
            while offset < total_len:
                payload = bytearray()
                if offset == 0:
                    payload.extend(struct.pack("<H", total_len))
                    chunk = data[offset: offset + (max_payload - 2)]
                else:
                    chunk = data[offset: offset + max_payload]
                    
                payload.extend(chunk)
                offset += len(chunk)
                
                fc = frame_ctrl
                if offset < total_len:
                    fc |= 0x10 # Set has_frag
                
                header = struct.pack("<BBBB", type_val, fc, self.seq, len(payload))
                self.seq = (self.seq + 1) % 256
                try:
                    await self.client.write_gatt_char(self.write_char, header + payload, response=True)
                except Exception as e:
                    _LOGGER.error(f"[{self.address}] Error writing fragment to GATT: {e}")
                await asyncio.sleep(0.3) # Increased to 0.3s to save Pi BT Stack

    def _generate_auth_payload(self):
        import time, json, uuid, struct
        try:
            import zstandard as zstd
        except ImportError:
            return bytearray()
            
        current_time = int(time.time())
        json_obj = {
            "cmdData": {
                "deviceModel": "TB132FU",
                "lengthUnit": "cm",
                "mode": "direct",
                "temperatureUnit": "C",
                "userId": "291396634634354689" if self.is_wt11 else "628756626317344770",
                "weightUnit": "g"
            },
            "cmdId": uuid.uuid4().hex,
            "cmdSeqNo": 1,
            "cmdType": "BT:apply:trust",
            "deviceId": self.address.replace(":", ""),
            "deviceType": "WT11" if self.is_wt11 else "WT10",
            "protocol": "BT",
            "serverTime": current_time * 1000,
            "serverTimeSecond": current_time
        }
        json_str = json.dumps(json_obj, separators=(",", ":")).encode("utf-8")
        
        cctx = zstd.ZstdCompressor(level=3)
        comp = cctx.compress(json_str)

        payload = bytearray(b"\xaa\xaa")
        payload.extend(struct.pack("<H", len(comp)))
        payload.extend(struct.pack("<H", len(json_str)))
        payload.extend(comp)
        
        def crc16_ccitt_false_local(data):
            crc = 0
            for b in data:
                crc = crc ^ (b << 8)
                for _ in range(8):
                    if crc & 0x8000:
                        crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                    else:
                        crc = (crc << 1) & 0xFFFF
            return crc

        pkg_crc = crc16_ccitt_false_local(payload[2:])
        real_crc = crc16_ccitt_false_local(json_str)

        payload.extend(struct.pack("<H", pkg_crc))
        payload.extend(struct.pack("<H", real_crc))

        return payload

    async def _negotiate_security(self):
        if getattr(self, '_negotiating', False):
            return
        self._negotiating = True
        try:
            await asyncio.sleep(2)
            _LOGGER.error(f"[{self.address}] Starting Typhur security negotiation...")
            
            # 1. Custom Typhur JSON Auth
            auth_payload = self._generate_auth_payload()
            if auth_payload:
                await self._post(0x4D, 0x00, auth_payload)
                _LOGGER.error(f"[{self.address}] Sent Auth payloads")
                
                import time, json, uuid
                try:
                    import zstandard as zstd
                except ImportError:
                    pass
                
                current_time = int(time.time())
                device_type_str = "WT11" if self.is_wt11 else "WT10"
                user_id_str = "291396634634354689" if self.is_wt11 else "628756626317344770"
                
                json_obj2 = {
                    "cmdData": {},
                    "cmdId": uuid.uuid4().hex,
                    "cmdSeqNo": 2,
                    "cmdType": f"{device_type_str}:status:request",
                    "deviceId": self.address.replace(":", ""),
                    "deviceType": device_type_str,
                    "protocol": "BT",
                    "serverTime": current_time * 1000,
                    "serverTimeSecond": current_time
                }
                json_str2 = json.dumps(json_obj2, separators=(",", ":")).encode("utf-8")
                comp2 = zstd.ZstdCompressor(level=3).compress(json_str2)
                payload2 = bytearray(b"\xaa\xaa")
                payload2.extend(struct.pack("<H", len(comp2)))
                payload2.extend(struct.pack("<H", len(json_str2)))
                payload2.extend(comp2)
                
                def crc16_ccitt_false_local(data):
                    crc = 0
                    for b in data:
                        crc = crc ^ (b << 8)
                        for _ in range(8):
                            if crc & 0x8000:
                                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                            else:
                                crc = (crc << 1) & 0xFFFF
                    return crc

                pkg_crc2 = crc16_ccitt_false_local(payload2[2:])
                real_crc2 = crc16_ccitt_false_local(json_str2)
                payload2.extend(struct.pack("<H", pkg_crc2))
                payload2.extend(struct.pack("<H", real_crc2))
                
                await asyncio.sleep(0.5)
                await self._post(0x4D, 0x00, payload2)
                _LOGGER.error(f"[{self.address}] Sent WIFI request")
                # 3. Send BT:cooking:data:request
                json_obj3 = {
                    "cmdData": {},
                    "cmdId": uuid.uuid4().hex,
                    "cmdSeqNo": 3,
                    "cmdType": "BT:cooking:data:request",
                    "deviceId": self.address.replace(":", ""),
                    "deviceType": device_type_str,
                    "protocol": "BT",
                    "serverTime": current_time * 1000,
                    "serverTimeSecond": current_time
                }
                json_str3 = json.dumps(json_obj3, separators=(",", ":")).encode("utf-8")
                comp3 = zstd.ZstdCompressor(level=3).compress(json_str3)
                payload3 = bytearray(b"\xaa\xaa")
                payload3.extend(struct.pack("<H", len(comp3)))
                payload3.extend(struct.pack("<H", len(json_str3)))
                payload3.extend(comp3)
                pkg_crc3 = crc16_ccitt_false_local(payload3[2:])
                real_crc3 = crc16_ccitt_false_local(json_str3)
                payload3.extend(struct.pack("<H", pkg_crc3))
                payload3.extend(struct.pack("<H", real_crc3))
                
                await asyncio.sleep(0.5)
                await self._post(0x4D, 0x00, payload3)
                _LOGGER.error(f"[{self.address}] Sent cooking:data:request")
        except Exception as e:
            _LOGGER.error(f"[{self.address}] Negotiation failed: {e}")
        finally:
            self._negotiating = False
            return

    def _on_notify(self, sender, data):
        try:
            _LOGGER.error(f"[{self.address}] GOT NOTIFY FROM {sender} (Handle: {getattr(sender, 'handle', 'N/A')}): Vendor specific with {len(data)} bytes")
            self.rx_buf.extend(data)
            
            while len(self.rx_buf) >= 4:
                type_val = self.rx_buf[0]
                frame_ctrl = self.rx_buf[1]
                seq = self.rx_buf[2]
                payload_len = self.rx_buf[3]
                
                is_encrypted = (frame_ctrl & 0x08) != 0
                has_frag = (frame_ctrl & 0x10) != 0
                
                # Check for error packets (Type 1, Subtype 12)
                if type_val == 0x31:  # 0x31 = 49 = Type 1 (Ctrl) | Subtype 12 (Error) << 2
                    _LOGGER.error(f"[{self.address}] Received BLUFI ERROR packet from device! Payload hex might be in rx_buf")
                
                _LOGGER.error(f"[{self.address}] Pkt: type={type_val:02x}, ctrl={frame_ctrl:02x}, seq={seq}, len={payload_len}, frag={has_frag}, enc={is_encrypted}")
                
                if len(self.rx_buf) < 4 + payload_len:
                    break # Wait for more data
                    
                payload = self.rx_buf[4:4+payload_len]
                self.rx_buf = self.rx_buf[4+payload_len:]
                
                if has_frag:
                    if type_val == 0x4D:
                        if len(payload) >= 2:
                            frag_len = struct.unpack('<H', payload[:2])[0]
                            payload = payload[2:]
                    self.pub_key_buf.extend(payload)
                    continue
                else:
                    if self.pub_key_buf:
                        self.pub_key_buf.extend(payload)
                        full_payload = self.pub_key_buf
                        self.pub_key_buf = bytearray()
                        _LOGGER.error(f"[{self.address}] Fragment assembly complete! Assembled payload length: {len(full_payload)}")
                    else:
                        full_payload = payload
                
                if is_encrypted and self.aes_key:
                    iv = self._generate_iv(seq)
                    cipher = Cipher(algorithms.AES(self.aes_key), modes.CFB(iv))
                    decryptor = cipher.decryptor()
                    full_payload = bytearray(decryptor.update(bytes(full_payload)) + decryptor.finalize())
                
                self._handle_payload(type_val, full_payload)
        except Exception as e:
            _LOGGER.error(f"[{self.address}] _on_notify crashed: {e}")

    def _handle_payload(self, type_val, payload):
        pkg_type = type_val % 4
        sub_type = type_val >> 2
        _LOGGER.error(f"[{self.address}] Handle payload: type={pkg_type}, sub={sub_type}, len={len(payload)}, raw={payload.hex()}")
        
        if pkg_type == 1 and sub_type == 0:
            self.pub_key_buf.extend(payload)
            if len(self.pub_key_buf) >= 128:
                self.aes_key = self.crypto.derive_shared_key(self.pub_key_buf[:128])
                self.pub_key_buf = bytearray()
                self.has_received_peer_key = True
                _LOGGER.error(f"[{self.address}] Derived AES key")
        elif pkg_type == 1 and sub_type == 18:
            # Reconnection or WT11 init
            if self.is_wt11:
                self.has_received_peer_key = True # Force unblock
                _LOGGER.error(f"[{self.address}] Received Subtype 18! WT11 is ready for auth payloads.")
            else:
                _LOGGER.error(f"[{self.address}] Received Subtype 18! WT10 is responding, waiting for DH key...")
        elif pkg_type == 1 and sub_type == 19:
            pass # Handled below
        elif not self.is_wt11 and len(payload) >= 14:
            # Maybe WT10 sends data outside of subtype 19?
            try:
                probe_id = payload[0]
                cur_temp = struct.unpack("<H", payload[1:3])[0]
                ambient_temp = struct.unpack("<H", payload[3:5])[0]
                battery = payload[5]
                
                data = {
                    "probe_id": probe_id,
                    "cur_temp": cur_temp,
                    "ambient_temp": ambient_temp,
                    "battery_level": battery
                }
                _LOGGER.error(f"[{self.address}] SUCCESS! Decoded WT10 binary payload from type={pkg_type},sub={sub_type}: {data}")
                if self.callback:
                    self.callback(data)
                return
            except Exception:
                pass
                
        if pkg_type == 1 and sub_type == 19:
            try:
                import zstandard as zstd
                
                magic_idx = payload.find(b'\x28\xb5\x2f\xfd')
                if magic_idx == -1:
                    try:
                        # Try parsing as raw uncompressed JSON (just in case)
                        data = json.loads(payload.decode('utf-8', errors='ignore'))
                        if self.callback:
                            self.callback(data)
                        return
                    except:
                        pass
                        
                    # It might be WT10 binary sensor data!
                    if not self.is_wt11 and len(payload) >= 14:
                        try:
                            # Parse WT10 binary format
                            probe_id = payload[0]
                            cur_temp = struct.unpack("<H", payload[1:3])[0]
                            ambient_temp = struct.unpack("<H", payload[3:5])[0]
                            battery = payload[5]
                            
                            data = {
                                "probe_id": probe_id,
                                "cur_temp": cur_temp,
                                "ambient_temp": ambient_temp,
                                "battery_level": battery
                            }
                            _LOGGER.error(f"[{self.address}] SUCCESS! Decoded WT10 binary payload: {data}")
                            if self.callback:
                                self.callback(data)
                            return
                        except Exception as e:
                            _LOGGER.error(f"[{self.address}] Failed parsing WT10 binary: {e}")
                            
                    return
                
                clean_payload = payload[magic_idx:]
                dctx = zstd.ZstdDecompressor()
                
                for drop in range(25):
                    try:
                        p = clean_payload[:len(clean_payload)-drop] if drop > 0 else clean_payload
                        dec = dctx.decompress(p)
                        if dec:
                            if b'{' in dec:
                                data = json.loads(dec[dec.find(b'{'):].decode('utf-8'))
                                _LOGGER.error(f"[{self.address}] SUCCESS! Decoded JSON payload dropping {drop} bytes")
                                if self.callback:
                                    self.callback(data)
                                return
                    except zstd.ZstdError:
                        continue
            except Exception as e:
                _LOGGER.error(f"[{self.address}] Zstandard exception: {e}")
                
        # Try raw JSON fallback regardless of pkg_type for WT10
        try:
            if b'{' in payload:
                json_str = payload[payload.find(b'{'):].decode('utf-8', errors='ignore')
                data = json.loads(json_str)
                _LOGGER.error(f"[{self.address}] SUCCESS! Decoded uncompressed JSON payload")
                if self.callback:
                    self.callback(data)
        except Exception:
            pass

    async def _post_set_security(self):
        # 0 | (4 << 2) was observed to wake up the WT10 probe telemetry stream
        await self._post(0 | (4 << 2), 0x00, bytearray([0x02]))
        _LOGGER.error(f"[{self.address}] Security setup complete. Waiting for data...")