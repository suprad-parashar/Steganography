# Secure Steganography (securesteg)

A simple Steganography library with additional security features.

Developed by Suprad S Parashar (c) 2021 - MIT License

## Installation

Install securesteg using pip using the following command

```cmd
pip install securesteg
```

## Encoding Data to image
### 1. Import securesteg

```python
import securesteg as ss
```

### 2. Create an instance of SecureSteganography and set the data

```python
data = "A quick brown fox jumps over the lazy dog."
image = ss.SecureSteganography(IMAGE_PATH)
image.set_data(data)
```

### 4. Add Security

You can choose from the following - 

**MAC Address** - Only the device having the Target MAC Address can decode the image.
Specify target as the target MAC Address.
Set target as "FF:FF:FF:FF:FF:FF" to allow all devices.

**Password** - Can be decoded with a password.

```python
# MAC Address
image.secure(security='mac', target='FF:FF:FF:FF:FF:FF')

# Password
image.secure(security='password', password='SecurePassword')
```

### 5. Add Encryption to the data

You can currently add Caesar Cipher Encryption to the data.

```python
# Caesar Cipher
image.encrypt(encrypt='caesar', n=19)
```

### 6. Encode the data and save the new image.

```python
image.encode()
image.save(SAVE_PATH) 
```

## Decoding data from image
```python
image = ss.SecureSteganography(IMAGE_PATH)
message = image.decode()
print(f"Decoded Message: {message}")

# Pass in additional parameters such as passwords as args
message = image.decode(password='SecurePassword')
print(f"Decoded Message: {message}")
```
