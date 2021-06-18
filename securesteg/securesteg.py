from PIL import Image
from getmac import get_mac_address as gma
import hashlib
from bitstring import ConstBitStream


def get_bits(header_length_bits, header_length, header, data_length_bits, data_length, data, is_file=False) -> list[int]:
	bits = []
	for bit in header_length_bits + data_length_bits + header_length + data_length:
		bits.append(int(bit))
	for c in header:
		bits.extend(map(int, [i for i in format(ord(c), "08b")]))
	if is_file:
		bits.extend(data)
	else:
		for c in data:
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


def get_metadata(metadata, is_file=False) -> (str, str):
	n = len(metadata) * (1 if is_file else 8)
	if n == 0:
		length_bits = "000"
		length = ""
	elif n < 256:
		length_bits = "001"
		length = bin(n).replace("0b", "").zfill(8)
	elif n < 65536:
		length_bits = "010"
		length = bin(n).replace("0b", "").zfill(16)
	elif n < 4294967296:
		length_bits = "011"
		length = bin(n).replace("0b", "").zfill(32)
	else:
		length_bits = "100"
		length = bin(n).replace("0b", "").zfill(64)
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


def create_file(target_bits, file_name):
	output = "".join(map(str, target_bits))
	i = 0
	buffer = bytearray()
	while i < len(output):
		buffer.append(int(output[i:i + 8], 2))
		i += 8
	with open(file_name, 'bw') as file:
		file.write(buffer)


class SecureSteganography:
	def __init__(self, image_path: str):
		self.image_path = image_path
		self.header = {}
		self.is_file = None
		self.data = None
		self.file = []
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

	def set_data(self, data: str, is_file=False, save_name=None) -> None:
		self.is_file = is_file
		self.header["is_file"] = is_file
		if not is_file:
			self.data = data
		else:
			file = ConstBitStream(filename=data)
			self.header['file_name'] = save_name or data
			self.file = list(map(int, file.bin))

	def encode(self) -> None:
		if self.data is None and self.file is None:
			raise Exception("No Data to Encode. Call set_data method to add data")
		image = Image.open(self.image_path, "r")
		header = ""
		for key in self.header.keys():
			header += key + ":" + str(self.header[key]) + "\n"

		header_length, header_length_bits = get_metadata(header)
		if self.is_file:
			data_length, data_length_bits = get_metadata(self.file, True)
		else:
			data_length, data_length_bits = get_metadata(self.data)

		if self.is_file:
			total_size = 3 + len(header_length) + (len(header) * 8) + 3 + len(data_length) + (len(self.file))
		else:
			total_size = 3 + len(header_length) + (len(header) * 8) + 3 + len(data_length) + (len(self.data) * 8)
		if total_size > (image.size[0] * image.size[1]) * 3:
			raise Exception("Message is too long for this image.")
		k = 0
		if self.is_file:
			bits = get_bits(header_length_bits, header_length, header, data_length_bits, data_length, self.file, True)
		else:
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
		if self.is_file:
			raise Exception("Cannot Further encrypt files. Encryption possible with string data")
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
					if bool(self.header["is_file"]):
						create_file(target_bits, kwargs.get('save_path', None) or self.header["file_name"])
						return f"File extracted from image is stored at {kwargs.get('save_path', None) or self.header['file_name']}"
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
