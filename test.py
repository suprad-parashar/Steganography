import code

PATH = "D:/myCode/Python/Steganography/image.jpeg"
SAVE_PATH = "D:/myCode/Python/Steganography/secret.png"

data = "The quick 2 brown foxes, jump over the 3 lazy dogs."
print("Encoding...")
image = code.SecureSteganography(PATH)
image.set_data(data)
print(image.data)
image.encrypt(encrypt = 'caesar', n = 19)
print(image.data)
image.secure(security = 'mac', target = 'FF:FF:FF:FF:FF:FF')
image.encode()
image.save(SAVE_PATH)
print("Encoded")

print("Decoding...")
image = code.SecureSteganography(SAVE_PATH)
print("Decoded Message: " + image.decode())
# print(code.encrypt(data, method = "caesar", n = 23))

'''

image = SecureSteganography(imagePath)
image.hide(data, method="", encrypt="caesar", encypt_n=23, security='mac', target='ff:ff:ff:ff:ff:ff')
image.save(path)
image.close()

'''