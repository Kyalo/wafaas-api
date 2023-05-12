# # On the sending server
# import json

# header, key, cipher_text, tag, nonce = encrypt_data('secret data')

# # Encode the values into a dictionary
# data = {
#     'header': header.hex(),
#     'key': key.hex(),
#     'cipher_text': cipher_text.hex(),
#     'tag': tag.hex(),
#     'nonce': nonce.hex(),
# }

# # Convert the dictionary to a JSON string
# json_data = json.dumps(data)

# # Send the JSON string to the receiving server
# send_data_to_receiving_server(json_data)

# # On the receiving server
# import json

# # Receive the JSON string from the sending server
# json_data = receive_data_from_sending_server()

# # Convert the JSON string to a dictionary
# data = json.loads(json_data)

# # Decode the hex values and reconstruct the necessary variables
# header = bytes.fromhex(data['header'])
# key = bytes.fromhex(data['key'])
# cipher_text = bytes.fromhex(data['cipher_text'])
# tag = bytes.fromhex(data['tag'])
# nonce = bytes.fromhex(data['nonce'])

# # Decrypt the data using the reconstructed variables
# plain_text = decrypt_data(header, key, cipher_text, tag, nonce)

