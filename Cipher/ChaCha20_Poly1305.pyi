from typing import Union, Tuple, overload, Optional

Buffer = bytes|bytearray|memoryview

class ChaCha20Poly1305Cipher:
    nonce: bytes

    def __init__(self, key: Buffer, nonce: Buffer) -> None: ...
    def update(self, data: Buffer) -> None: ...
    @overload
    def encrypt(self, plaintext: Buffer) -> bytes: ...
    @overload
    def encrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...
    @overload
    def decrypt(self, plaintext: Buffer) -> bytes: ...
    @overload
    def decrypt(self, plaintext: Buffer, output: Union[bytearray, memoryview]) -> None: ...
    def digest(self) -> bytes: ...
    def hexdigest(self) -> str: ...
    def verify(self, received_mac_tag: Buffer) -> None: ...
    def hexverify(self, received_mac_tag: str) -> None: ...
    def encrypt_and_digest(self, plaintext: Buffer) -> Tuple[bytes, bytes]: ...
    def decrypt_and_verify(self, ciphertext: Buffer, received_mac_tag: Buffer) -> bytes: ...

def new(key: Buffer, nonce: Optional[Buffer] = ...) -> ChaCha20Poly1305Cipher: ...

block_size: int
key_size: int
