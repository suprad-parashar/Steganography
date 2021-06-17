import code

IMAGE_PATH = "Put the path of the image"

print("Decoding...")
image = code.SecureSteganography(IMAGE_PATH)
print("Decoded Message: " + image.decode())