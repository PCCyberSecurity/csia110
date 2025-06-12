import requests

# URL of the login endpoint
url = "https://formspree.io/f/myzyjpve"

# Login credentials
payload = {
    'email': 'bob@smith.com',
    'message': 'This is a message'
}

# Send POST request
response = requests.post(url, data=payload)

# Check the response
print(f"Status Code: {response.status_code}")
print(f"Response Body:\n{response.text}")
