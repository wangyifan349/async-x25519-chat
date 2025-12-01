from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# 生成 Alice 的 X25519 密钥对
alice_private = x25519.X25519PrivateKey.generate()
alice_public = alice_private.public_key()

# 生成 Bob 的 X25519 密钥对
bob_private = x25519.X25519PrivateKey.generate()
bob_public = bob_private.public_key()

# Alice 使用她的私钥和 Bob 的公钥计算共享秘密
alice_shared_secret = alice_private.exchange(bob_public)

# Bob 使用他的私钥和 Alice 的公钥计算共享秘密
bob_shared_secret = bob_private.exchange(alice_public)

# 验证共享秘密相等
if alice_shared_secret != bob_shared_secret:
    raise RuntimeError("共享秘密不匹配")

# 使用 HKDF-SHA256 从共享秘密派生 32 字节对称密钥（AES-256）
hkdf_alice = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'X25519 handshake demo v1')
alice_symmetric_key = hkdf_alice.derive(alice_shared_secret)

hkdf_bob = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'X25519 handshake demo v1')
bob_symmetric_key = hkdf_bob.derive(bob_shared_secret)

# 验证对称密钥相等
if alice_symmetric_key != bob_symmetric_key:
    raise RuntimeError("对称密钥不匹配")

# 要加密的明文和关联数据
plaintext = b"Hello Bob, this is Alice."
associated_data = b"protocol-v1"

# Alice 使用 AES-GCM 加密（生成随机 12 字节 nonce）
aesgcm_alice = AESGCM(alice_symmetric_key)
nonce = os.urandom(12)
ciphertext = aesgcm_alice.encrypt(nonce, plaintext, associated_data)

# Bob 使用相同对称密钥和相同 nonce 解密
aesgcm_bob = AESGCM(bob_symmetric_key)
decrypted = aesgcm_bob.decrypt(nonce, ciphertext, associated_data)
print("明文：", decrypted.decode())
