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

### 2. Create an instance of SecureSteganography

```python
image = ss.SecureSteganography(IMAGE_PATH)
```

### 3. Set Data

The data to hide can be a file or a string.

```python
# For Text Data
message = "A quick brown fox jumps over the lazy dog.
image.set_data(message)

# For Files
image.set_data(FILE_PATH, True) # The extracted file will be saved with the same name and path of the FILE_PATH
# or
image.set_data(FILE_PATH, True, SAVE_PATH) # The extracted file will be saved with the name and path as given in SAVE_PATH
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

# Pass in custom save_path in decode for extracting and saving files from the image.
message = image.decode(save_path="C:/Downloads")
```
