from PIL import Image
from getmac import get_mac_address as gma

class SecureSteganography:
	def __init__(self, image_path: str):
		self.image_path = image_path
		self.header = {}
		self.data = None
		self.image = None

	def get_bits(self, lone_bits: list, data: str) -> list:
		bits = []
		for bit in lone_bits:
			bits.append(int(bit))
		for c in data:
			bits.extend(map(int, [i for i in format(ord(c), "08b")]))
		return bits

	def secure(self, **kwargs):
		if kwargs.get("security", None) == 'mac':
			self.header['security'] = 'mac'
			self.header['target'] = kwargs['target'].upper()

	def set_data(self, data):
		self.data = data

	def encode(self):
		image = Image.open(self.image_path, "r")
		header = ""
		for key in self.header.keys():
			header += key + ":" + str(self.header[key]) + "\n"
		if len(header) == 0:
			header_length_bits = "000"
			header_length = ""
		elif len(header) * 8 < 256:
			header_length_bits = "001"
			header_length = bin(len(header) * 8).replace("0b", "").zfill(8)
		elif len(header) * 8 < 65536:
			header_length_bits = "010"
			header_length = bin(len(header) * 8).replace("0b", "").zfill(16)
		else:
			header_length_bits = "011"
			header_length = bin(len(header) * 8).replace("0b", "").zfill(32)
		message = header + self.data + "$"
		if 3 + len(header_length) + (len(message) * 8) > (image.size[0] * image.size[1]) * 3:
			raise Exception("Message is too long for this image.")
		k = 0
		bits = self.get_bits(header_length_bits + header_length, message)
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
	def save(self, save_path):
		if self.image is None:
			return
		self.image.save(save_path)
		self.image.close()

	def get_message(self, bits):
		k = 0
		message = ""
		while k < len(bits):
			letter = chr(int("".join(map(str, bits[k:k + 8])), 2))
			if letter == '$':
				break
			message += letter
			k += 8
		return message

	def encrypt(self, **kwargs):
		if self.data == None:
			raise Exception("Data not present to encrypt. Call object.set_data(data) method")
		if kwargs.get("encrypt", None) == 'caesar':
			n = kwargs.get("n", 0)
			if n != 0:
				self.header['encrypt'] = 'caesar'
				self.header['n'] = kwargs.get("n", 0)
				result = ""
				for i in range(len(self.data)):
					char = self.data[i]
					if (char.isupper()):
						result += chr((ord(char) + n - 65) % 26 + 65)
					elif char.islower():
						result += chr((ord(char) + n - 97) % 26 + 97)
					else:
						result += char
				self.data = result
	
	def get_header(self, bits):
		header_data = self.get_message(bits)
		header = {}
		for line in header_data.strip().split("\n"):
			key, value = line.split(":", 1)
			header[key] = value
		return header

	def check_security_access(self):
		try:
			if self.header.get("security", None) == 'mac':
				current_mac = gma().upper()
				if self.header["target"] == current_mac or self.header["target"] == "FF:FF:FF:FF:FF:FF":
					return True, ""
				else:
					return False, "Message Not Intended for you"
			return True, ""
		except:
			return False, "Missing Data in Image"

	def decrypt(self, message):
		if self.header.get('encrypt', None) == 'caesar':
			result = ""
			n = 26 - int(self.header['n'])
			for i in range(len(message)):
				char = message[i]
				if (char.isupper()):
					result += chr((ord(char) + n - 65) % 26 + 65)
				elif char.islower():
					result += chr((ord(char) + n - 97) % 26 + 97)
				else:
					result += char
			self.data = result

	def decode(self):
		image = Image.open(self.image_path, "r")
		bits = []
		flag = False
		check = False
		length_check = False
		header_length = 0
		pix = image.getpixel((0, 0))
		header_length_bits = "".join(map(str, [pix[0] % 2, pix[1] % 2, pix[2] % 2]))
		if header_length_bits == "000":
			header_length_check = 0
		elif header_length_bits == "001":
			header_length_check = 8
		elif header_length_bits == "010":
			header_length_check = 16
		elif header_length_bits == "011":
			header_length_check = 32
		for i in range(image.size[0]):
			for j in range(image.size[1]):
				pixel = image.getpixel((i, j))
				for k in range(3):
					bits.append(pixel[k] % 2)
				if not check and header_length_check != 0:
					if not length_check and len(bits) >= (3 + header_length_check):
						length_check = True
						header_length = int("".join(map(str, bits[3:3 + header_length_check])), 2)
					if length_check and not check and len(bits) >= 3 + header_length_check + header_length:
						check = True
						flag = True
			if flag:
				target_bits = bits[3 + header_length_check:3 + header_length_check + header_length]
				self.header = self.get_header(target_bits)
				access_granted, security_message = self.check_security_access()
				if access_granted:
					check = True
					flag = False
				else:
					return security_message
		message = self.get_message(bits[3 + header_length_check + header_length:])
		self.decrypt(message)
		return self.data