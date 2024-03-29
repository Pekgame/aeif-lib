# AEIF (AES Encrypted Image File) Library

The **AEIF** (AES Encrypted Image File) library is a Python library that provides functionality for encrypting and decrypting image files using the AES encryption algorithm.

## **Installation**

You can install the AEIF library using pip:

```bash
pip install aeif-lib
```

## **Usage**

### Generating a key

To generate a key, you can use the `genkey` function:

```python
from aeif_lib import genkey

# Generate a random key with the specified size
# (only 16, 24, and 32 bytes is supported) and save it to a file
key_path, key = genkey("path/to/save/key")
```

### Encrypting an image

To encrypt an image, you can use the `encrypt` function:

```python
from aeif_lib import AEIFManager, genkey, verify_hash

key_path, _ = genkey("path/to/save/key", 32)

# Create an AEIFManager object
# (key_path is optional but will be required for encryption/decryption if not set)
aeif = AEIFManager(key_path)

# Encrypt the image (key or key_path is optional if the key is already set)
aeif.encrypt("./img.png", "./img_e.aeif")
```

### Decrypting an image

To decrypt an image, you can use the `decrypt` function:

```python
from aeif_lib import AEIFManager

key_path = "path/to/the/key"

# Create an AEIFManager object
# (key_path is optional but will be required for encryption/decryption if not set)
aeif = AEIFManager(key_path)

# Decrypt the image (key or key_path is optional if the key is already set)
aeif.decrypt("./img_e.aeif", "./img_d.png")

# Verify the hash of the original image and the decrypted image
verify = verify_hash(("./img.png", "./img_d.png"))
print("Hashes match!" if verify else "Hashes do not match!")
```
