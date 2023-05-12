"""
 This code imports the `os` and `sys` modules, adds the `/api/lib/` directory to the Python interpreter's
 search path, imports the `decrypt_data` function from the `Encryption_decryption` module from the 
 `api/lib/` directory,  imports the `format_exc()` function from the `traceback` module, prints 
 the content type header, checks if the `HTTP_X_CONTENT_FIELD_WAF` environment variable is set and 
 its value is not empty, and if it is, tries to decrypt the content of the environment variable and 
 prints the decrypted content, otherwise prints the index page.
"""

import os 
import sys 

# Add the `/api/lib/` directory to the Python interpreter's search path.
sys.path.insert(0, "/home/dmore/new_codespace/wafaas-api/api/lib/")

# Import the `decrypt_data` function from the `Encryption_decryption` module from the `api/lib/` directory.
from Encryption_decryption import decrypt_data

# Import the `format_exc()` function from the `traceback` module.
from traceback import format_exc

# Print the content type header.
print("Content-type:text/html\n\n")

# Check if the `HTTP_X_CONTENT_FIELD_WAF` environment variable is set and its value is not empty.
if "HTTP_X_CONTENT_FIELD_WAF" in os.environ and len(os.environ["HTTP_X_CONTENT_FIELD_WAF"]) > 0:

    # Try to decrypt the content of the environment variable and print the decrypted content.
    try:
        content = os.environ["HTTP_X_CONTENT_FIELD_WAF"]      
        # print(decrypt_data(content))
        print(content)
        
    except Exception as e:

        # Print the exception information.
        print(format_exc())

else:

    # Print the index page.
    print("<html><body>Index</body></html>")
