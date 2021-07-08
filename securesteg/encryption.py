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
