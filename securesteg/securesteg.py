from PIL import Image
from getmac import get_mac_address as gma
import hashlib
from bitstring import ConstBitStream
from typing import Union


def get_bits(header_length_bits: str, header_length: str, header: str, data_length_bits: str, data_length: str, data: Union[list[int], str], is_file: bool = False) -> list[int]:
	"""
	Function which takes in the metadata and the actual data to be incorporated into the images and converts them into bits.

	@:param header_length_bits -> The length of the header length code, eg. 000, 100, etc. 3 bits.
	@:param header_length -> The number of bits comprising the header data. (Formatted to 0, 8, 16, 32, etc).
	@:param header -> The metadata to be added to the image.
	@:param data_length_bits -> The length of the data length code, eg. 000, 100, etc. 3 bits.
	@:param data_length -> The number of bits comprising the data. (Formatted to 0 bits, 8 bits, 16 bits, 32 bits, etc).
	@:param data -> The data to be added to the image.
	@:param is_file -> A boolean which is True if the data passed is a file, otherwise False. [Default = False]

	@:return -> List of integers containing the bits.
	"""

	# Initialise Bits List.
	bits = []

	# Add the Metadata bits into the list.
	for bit in header_length_bits + data_length_bits + header_length + data_length:
		bits.append(int(bit))

	# Add the characters (8-bit binary) of the header to the bit list.
	for character in header:
		bits.extend(map(int, [bit for bit in format(ord(character), "08b")]))

	# Add bits directly if the data is a file, else convert the character to 8-bit form and append to the bit list.
	if is_file:
		bits.extend(data)
	else:
		for character in data:
			bits.extend(map(int, [bit for bit in format(ord(character), "08b")]))

	# Return the bit List.
	return bits


def get_message(bits: list[int]) -> str:
	"""
	Takes in the bits of the message and converts into readable message.

	@:param -> The bits of the image.

	@:return -> Message encoded in the image.
	"""

	# Initialise Data Variables.
	count_bits_added = 0
	message = []

	# Fetch 8 bits and convert it into a letter. Exit at '$'.
	while count_bits_added < len(bits):
		letter = chr(int("".join(map(str, bits[count_bits_added:count_bits_added + 8])), 2))  # Reading 8 bits at a time and converting it to a character.
		if letter == '$':  # Check if reached end of message.
			break
		message.append(letter)
		count_bits_added += 8

	# Return the message obtained.
	return "".join(message)


def get_header(bits: list[int]) -> dict:
	"""
	Function to return the header from the bits obtained from the image.

	@:param bits -> The bits obtained from the image related to the header.

	@:return -> A Dictionary with the header values as Key-Value pair.
	"""

	# Get the header data in the form of string and initialise the Header Dictionary.
	header_data = get_message(bits)
	header = {}

	# Convert the header string into data store.
	for line in header_data.strip().split("\n"):
		key, value = line.split(":", 1)
		header[key] = value

	# Return the header dictionary.
	return header


def caesar_cipher(message: str, n: int) -> str:
	"""
	Encrypts the message using caesar cipher.

	@:param message -> The message to be encrypted.
	@:n -> The amount of places the message has to be shifted.

	@:return -> Encrypted Message.
	"""

	# Initialise Result string list.
	result = []

	# Shift each character in the message.
	for index in range(len(message)):
		char = message[index]
		if char.isupper():
			result.append(chr((ord(char) + n - 65) % 26 + 65))
		elif char.islower():
			result.append(chr((ord(char) + n - 97) % 26 + 97))
		elif char.isdigit():
			result.append(chr((ord(char) + n - 48) % 10 + 48))
		else:
			result.append(char)

	# Return the Cipher Text.
	return "".join(result)


def get_metadata(metadata: Union[str, list[int]], is_file: bool = False) -> (str, str):
	"""
	Finds and returns the length_code and the length of the metadata

	@:param metadata -> The data whose length_code and length is to be calculated.
	@:param is_file -> A boolean which is True if the data passed is a file, otherwise False. [Default = False]

	@:return -> A tuple containing the length and the length_code of the metadata.
	"""

	# Obtain the total bits.
	total_bits = len(metadata) * (1 if is_file else 8)

	# Assign the length_codes and length.
	if total_bits == 0:
		length_bits = "000"
		length = ""
	elif total_bits < 256:
		length_bits = "001"
		length = bin(total_bits).replace("0b", "").zfill(8)  	# Convert to binary and insert zeros at the beginning.
	elif total_bits < 65536:
		length_bits = "010"
		length = bin(total_bits).replace("0b", "").zfill(16)
	elif total_bits < 4294967296:
		length_bits = "011"
		length = bin(total_bits).replace("0b", "").zfill(32)
	else:
		length_bits = "100"
		length = bin(total_bits).replace("0b", "").zfill(64)

	# Return the length and the length_code.
	return length, length_bits


def get_length(pixel: tuple) -> int:
	"""
	The function returns the length code from the pixel.

	@:param pixel -> The pixel from which the length code is to be retrieved.
	@:return -> Number of bits to read to find the length of the metadata.
	"""

	# Get the length_code from the pixel.
	length_bits = "".join(map(str, [pixel[0] % 2, pixel[1] % 2, pixel[2] % 2]))

	# Get the length from the length_code.
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

	# Return length.
	return length


def create_file(target_bits: list[int], file_name: str):
	"""
	Create a file from its bits with the given filename.

	@:param target_bits -> The bits from which the file is to be created.
	@:param file_name -> The name of the file.
	"""

	# Create bit string from the bits.
	output = "".join(map(str, target_bits))

	# Initialise Bit Counter and buffer.
	bits_read = 0
	buffer = bytearray()

	# Read 8 bits and create file using the byte.
	while bits_read < len(output):
		buffer.append(int(output[bits_read:bits_read + 8], 2))
		bits_read += 8

	# Save the file.
	with open(file_name, 'bw') as file:
		file.write(buffer)


class SecureSteganography:
	"""
	The main SecureSteganography class.
	"""

	def __init__(self, image_path: str):
		"""
		The constructor of the Class.

		@:param image_path -> The path of the image which is to be opened.
		"""

		# The path of the image.
		self.image_path: str = image_path

		# The headers of the image which contain additional information about the data and decoding methods.
		self.header: dict = {}

		# Boolean to check if the data is a file or not.
		self.is_file: Union[bool, None] = None

		# The string data.
		self.data: Union[str, None] = None

		# The file bits.
		self.file: list[int] = []

		# The image object.
		self.image: 'Image' = None

	def secure(self, **kwargs) -> None:
		"""
		Adds security to the image encoding.

		:param kwargs: Keyword Arguments
		"""

		# Get the security method.
		security = kwargs.get('security', None)

		# Get Target MAC Address and add to header.
		if security == 'mac':
			self.header['security'] = 'mac'
			self.header['target'] = kwargs['target'].upper()
		# Get the password and add the hashed_version to the header.
		elif security == 'password':
			self.header['security'] = 'password'
			password = kwargs['password']
			hashed_password = hashlib.sha3_256(password.encode()).hexdigest()
			self.header['password'] = hashed_password

	def set_data(self, data: str, is_file: bool = False, decode_save_name: str = None) -> None:
		"""
		Sets the data to be hidden into the object.

		:param data: The data to be hidden.
		:param is_file: True if the data passed is a file, else False.
		:param decode_save_name: The name to be saved during decode.
		"""

		# Set variables.
		self.is_file = is_file
		self.header["is_file"] = is_file

		# Add data if not file.
		if not is_file:
			self.data = data
		else:
			file = ConstBitStream(filename=data)
			self.header['file_name'] = decode_save_name or data
			self.file = list(map(int, file.bin))  	# Get the bits of the file.

	def encode(self) -> None:
		"""
		Encodes(Hides) the Data into the image.
		"""

		# No data or file available.
		if self.data == "" and self.file == []:
			raise Exception("No Data to Encode. Call set_data method to add data")

		# Create image object with image_path.
		image = Image.open(self.image_path, "r")

		# Create header string from header dictionary.
		header = []
		for key in self.header.keys():
			header.append(key)
			header.append(":")
			header.append(str(self.header[key]))
			header.append("\n")
		header = "".join(header)

		# Get header Length and length_code
		header_length, header_length_bits = get_metadata(header)

		# Get data length and length_code.
		if self.is_file:
			data_length, data_length_bits = get_metadata(self.file, True)
		else:
			data_length, data_length_bits = get_metadata(self.data)

		# Find the total size of the message and headers.
		if self.is_file:
			total_size = 3 + len(header_length) + (len(header) * 8) + 3 + len(data_length) + (len(self.file))
		else:
			total_size = 3 + len(header_length) + (len(header) * 8) + 3 + len(data_length) + (len(self.data) * 8)

		# Check if space exists.
		if total_size > (image.size[0] * image.size[1]) * 3:
			raise Exception("Message is too long for this image.")

		# Get the bits of the entire message.
		if self.is_file:
			bits = get_bits(header_length_bits, header_length, header, data_length_bits, data_length, self.file, True)
		else:
			bits = get_bits(header_length_bits, header_length, header, data_length_bits, data_length, self.data)

		# Write bits to image.
		bits_written = 0
		done = False
		for i in range(image.size[0]):
			for j in range(image.size[1]):
				if bits_written < len(bits):
					try:
						a = bits[bits_written]
					except IndexError:
						a = 0
					try:
						b = bits[bits_written + 1]
					except IndexError:
						b = 0
					try:
						c = bits[bits_written + 2]
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
					bits_written += 3
				else:
					done = True
					break
			if done:
				break

		# Set image object to image.
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
				elif not header_check and length_check and len(
						bits) > 6 + header_length_size + data_length_size + header_length:
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
