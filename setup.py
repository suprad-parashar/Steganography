from setuptools import setup, find_packages

VERSION = '0.1.0'
DESCRIPTION = 'Simple Steganography with Added Security'
LONG_DESCRIPTION = 'A package that allows to hide data and files in images with added security such as Passwords, Encryption and MAC Addresses.'

# Setting up
setup(
	name="securesteg",
	version=VERSION,
	author="Suprad S Parashar",
	author_email="suprad.s.parashar@gmail.com",
	description=DESCRIPTION,
	long_description_content_type="text/markdown",
	packages=find_packages(),
	install_requires=['pillow', 'getmac', 'bitstring'],
	keywords=['python', 'image', 'data', 'hiding', 'steganography', 'secure'],
	classifiers=[
		"Development Status :: 1 - Planning",
		"Intended Audience :: Developers",
		"Programming Language :: Python :: 3",
		"Operating System :: Unix",
		"Operating System :: MacOS :: MacOS X",
		"Operating System :: Microsoft :: Windows",
	]
)
