from PIL import Image
from getmac import get_mac_address as gma
import hashlib


def get_bits(header_length_bits, header_length, header, data_length_bits, data_length, data) -> list[int]:
	bits = []
	for bit in header_length_bits + data_length_bits + header_length + data_length:
		bits.append(int(bit))
	for c in header + data:
		bits.extend(map(int, [i for i in format(ord(c), "08b")]))
	return bits


def get_message(bits: list[int]) -> str:
	k = 0
	message = ""
	while k < len(bits):
		letter = chr(int("".join(map(str, bits[k:k + 8])), 2))
		if letter == '$':
			break
		message += letter
		k += 8
	return message


def get_header(bits: list[int]) -> dict:
	header_data = get_message(bits)
	header = {}
	for line in header_data.strip().split("\n"):
		key, value = line.split(":", 1)
		header[key] = value
	return header


def caesar_cipher(message: str, n: int) -> str:
	result = ""
	for i in range(len(message)):
		char = message[i]
		if char.isupper():
			result += chr((ord(char) + n - 65) % 26 + 65)
		elif char.islower():
			result += chr((ord(char) + n - 97) % 26 + 97)
		elif char.isdigit():
			result += chr((ord(char) + n - 48) % 10 + 48)
		else:
			result += char
	return result


def get_metadata(metadata: str) -> (str, str):
	if len(metadata) == 0:
		length_bits = "000"
		length = ""
	elif len(metadata) * 8 < 256:
		length_bits = "001"
		length = bin(len(metadata) * 8).replace("0b", "").zfill(8)
	elif len(metadata) * 8 < 65536:
		length_bits = "010"
		length = bin(len(metadata) * 8).replace("0b", "").zfill(16)
	else:
		length_bits = "011"
		length = bin(len(metadata) * 8).replace("0b", "").zfill(32)
	return length, length_bits


def get_length(pixel):
	length_bits = "".join(map(str, [pixel[0] % 2, pixel[1] % 2, pixel[2] % 2]))
	if length_bits == "000":
		length = 0
	elif length_bits == "001":
		length = 8
	elif length_bits == "010":
		length = 16
	elif length_bits == "011":
		length = 32
	else:
		length = -1
	return length


class SecureSteganography:
	def __init__(self, image_path: str):
		self.image_path = image_path
		self.header = {}
		self.data = None
		self.image = None

	def secure(self, **kwargs) -> None:
		security = kwargs.get('security', None)
		if security == 'mac':
			self.header['security'] = 'mac'
			self.header['target'] = kwargs['target'].upper()
		elif security == 'password':
			self.header['security'] = 'password'
			password = kwargs['password']
			hashed_password = hashlib.sha3_256(password.encode()).hexdigest()
			self.header['password'] = hashed_password

	def set_data(self, data: str) -> None:
		self.data = data

	def encode(self) -> None:
		if self.data is None:
			raise Exception("No Data to Encode. Call set_data method to add data")
		image = Image.open(self.image_path, "r")
		header = ""
		for key in self.header.keys():
			header += key + ":" + str(self.header[key]) + "\n"

		header_length, header_length_bits = get_metadata(header)
		data_length, data_length_bits = get_metadata(self.data)

		total_size = 3 + len(header_length) + (len(header) * 8) + 3 + len(data_length) + (len(self.data) * 8)
		if total_size > (image.size[0] * image.size[1]) * 3:
			raise Exception("Message is too long for this image.")
		k = 0
		bits = get_bits(header_length_bits, header_length, header, data_length_bits, data_length, self.data)
		done = False
		for i in range(image.size[0]):
			for j in range(image.size[1]):
				if k < len(bits):
					try:
						a = bits[k]
					except IndexError:
						a = 0
					try:
						b = bits[k + 1]
					except IndexError:
						b = 0
					try:
						c = bits[k + 2]
					except IndexError:
						c = 0
					p1, p2, p3 = image.getpixel((i, j))
					if p1 % 2 != a:
						p1 += (-1 if p1 == 255 else 1)
					if p2 % 2 != b:
						p2 += (-1 if p2 == 255 else 1)
					if p3 % 2 != c:
						p3 += (-1 if p3 == 255 else 1)
					image.putpixel((i, j), (p1, p2, p3))
					k += 3
				else:
					done = True
					break
			if done:
				break
		self.image = image

	def save(self, save_path: str) -> None:
		if self.image is None:
			return
		self.image.save(save_path)
		self.image.close()

	def encrypt(self, **kwargs) -> None:
		if self.data is None:
			raise Exception("Data not present to encrypt. Call object.set_data(data) method")
		if kwargs.get("encrypt", None) == 'caesar':
			n = kwargs.get("n", 0)
			if n != 0:
				self.header['encrypt'] = 'caesar'
				self.header['n'] = n
				self.data = caesar_cipher(self.data, n)

	def check_security_access(self, kwargs) -> (bool, str):
		try:
			security = self.header.get("security", None)
			if security == 'mac':
				current_mac = gma().upper()

				if self.header["target"] == current_mac or self.header["target"] == "FF:FF:FF:FF:FF:FF":
					return True, ""
				else:
					return False, "Message Not Intended for you"
			elif security == 'password':
				password = kwargs.get('password', None)
				if password is None:
					return False, "Password not provided"
				hashed_password = hashlib.sha3_256(password.encode()).hexdigest()

				return (True, "") if self.header['password'] == hashed_password else (False, "Wrong Password")

			return True, ""
		except KeyError:
			return False, "Missing Data in Image"

	def decrypt(self, message: str) -> None:
		self.data = message
		encrypt = self.header.get('encrypt', None)
		if encrypt == 'caesar':
			n = -int(self.header['n'])
			self.data = caesar_cipher(message, n)

	def decode(self, **kwargs) -> str:
		image = Image.open(self.image_path, "r")
		bits = []
		header_check = False
		header_length = 0
		data_length = 0
		header_length_size = get_length(image.getpixel((0, 0)))
		data_length_size = get_length(image.getpixel((0, 1)))
		if data_length_size <= 0 or header_length == -1:
			return "No Data present in the image"
		length_check = False

		for i in range(image.size[0]):
			for j in range(image.size[1]):
				pixel = image.getpixel((i, j))
				for k in range(3):
					bits.append(pixel[k] % 2)
				if length_check and len(bits) > 6 + header_length_size + data_length_size + header_length + data_length:
					pre_length = 6 + header_length_size + data_length_size + header_length
					target_bits = bits[pre_length:pre_length + data_length]
					message = get_message(target_bits)
					self.decrypt(message)
					return self.data
				elif not header_check and length_check and len(bits) > 6 + header_length_size + data_length_size + header_length:
					if header_length != 0:
						pre_length = 6 + header_length_size + data_length_size
						target_bits = bits[pre_length:pre_length + header_length]
						self.header = get_header(target_bits)
						access_granted, security_message = self.check_security_access(kwargs)
						if not access_granted:
							return security_message
					header_check = True
				elif not length_check and len(bits) > 6 + header_length_size + data_length_size:
					pre_length = 6 + header_length_size
					data_length = int("".join(map(str, bits[pre_length:pre_length + data_length_size])), 2)
					length_check = True
				elif not length_check and len(bits) > 6 + header_length_size:
					pre_length = 6
					try:
						header_length = int("".join(map(str, bits[pre_length:pre_length + header_length_size])), 2)
					except ValueError:
						header_length = 0
