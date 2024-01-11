from aeif_lib import AEIFManager, genkey, verify_hash

# Generate a random key with the specified size (only 16, 24, and 32 bytes is supported) and save it to a file
key_path, key = genkey("./tests/key.akf", 24)

# Create an AEIFManager object (key_path is optional but will be required for encryption/decryption if not set)
aeif = AEIFManager(key_path)

# Encrypt the image (key or key_path is optional if the key is already set)
aeif.encrypt("./tests/img.png", "./tests/img_e.aeif")

# Decrypt the image (key or key_path is optional if the key is already set)
aeif.decrypt("./tests/img_e.aeif", "./tests/img_d.png")

# Verify the hash of the original image and the decrypted image
verify = verify_hash(("./tests/img.png", "./tests/img_d.png"))
print("Hashes match!" if verify else "Hashes do not match!")
