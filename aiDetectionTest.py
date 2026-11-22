import requests

req = requests.request("POST", "http://127.0.0.1:8081/input", data={"content": "Hello, world!"}, verify=False)
print(req.status_code)