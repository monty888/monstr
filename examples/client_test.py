from monstr.client.client import Client

with Client('ws://localhost:8888') as c:
    c.wait_connect()