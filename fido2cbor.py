import cbor  # Importing CBOR (Concise Binary Object Representation) for encoding/decoding
import math

# Sample FIDO URI
uri = 'FIDO:/091171638618359425600875612544265360800638321560589057402161289118412772572467679383310103525359078224614298314585214490061492183717880746340937917006594109321447142404'  # Replace with actual URI

# Extract the last part of the URI after the last '/'
ns = uri.split('/')[-1]

# Convert the extracted numeric string into bytes
byte_sequence = b''.join(
    int(n, 10).to_bytes(
        int(math.log2(10**len(n)) // 8),  # Calculate the number of bytes needed
        'little'  # Use little-endian byte order
    )
    for n in (ns[i: i + 17] for i in range(0, len(ns), 17))  # Process 17-character chunks
)

# Decode the byte sequence using CBOR
decoded_data = cbor.loads(byte_sequence)

# Mapping to Kotlin QRData class fields
qr_data = {
    'publicKey': decoded_data[0],  # Compressed public key
    'qrSecret': decoded_data[1],  # QR secret
    'tunnelServerDomains': decoded_data[2],  # Number of known domains
    'currentTime': decoded_data[3],  # Timestamp
    'canPerformTransactions': decoded_data[4],  # supports_linking (boolean)
    'operationHint': decoded_data[5]  # request_type (string)
}

# Convert to Kotlin QRData class format (mapping)
class QRData:
    def __init__(self, publicKey, qrSecret, tunnelServerDomains, currentTime, canPerformTransactions, operationHint):
        self.publicKey = publicKey
        self.qrSecret = qrSecret
        self.tunnelServerDomains = tunnelServerDomains
        self.currentTime = currentTime
        self.canPerformTransactions = canPerformTransactions
        self.operationHint = operationHint

    def print_data(self):
        print("QRData:")
        
        # Pretty print the byte array and hex representation
        print(f"publicKey (Hex): {self.publicKey.hex()}")
        print(f"publicKey (ByteArray): {list(self.publicKey)}")  # Print as a list of integers

        print(f"qrSecret (Hex): {self.qrSecret.hex()}")
        print(f"qrSecret (ByteArray): {list(self.qrSecret)}")  # Print as a list of integers
        
        print(f"tunnelServerDomains: {self.tunnelServerDomains}")
        print(f"currentTime: {self.currentTime}")
        print(f"canPerformTransactions: {self.canPerformTransactions}")
        print(f"operationHint: {self.operationHint}")


# Create an instance of the QRData class with the data
qr_data_instance = QRData(
    publicKey=qr_data['publicKey'],
    qrSecret=qr_data['qrSecret'],
    tunnelServerDomains=qr_data['tunnelServerDomains'],
    currentTime=qr_data['currentTime'],
    canPerformTransactions=qr_data['canPerformTransactions'],
    operationHint=qr_data['operationHint']
)

# Pretty print the QRData instance
qr_data_instance.print_data()
