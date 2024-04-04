import os
import asyncio
import websockets
import ssl
import logging

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

# set up SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    os.path.join(os.path.dirname(__file__), "certs/cert.pem"),
    os.path.join(os.path.dirname(__file__), "certs/key.pem"),
)


async def send_ping(websocket, path):
    i = 1
    while True:
        try:
            await websocket.send(f"Helllllllllllllllllllllllllllo {i}")
            message = await websocket.recv()
            print(message)
            i += 1
            await asyncio.sleep(0.5)
        except websockets.ConnectionClosed:
            print("Connection closed")
            break


start_server = websockets.serve(
    send_ping,
    # "::1",
    "localhost",
    9443,
    # 8080,
    ping_interval=5,
    ssl=ssl_context,
    logger=logging.getLogger("websockets.server"),
    # compression=None
)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()


# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/OU=OrganizationUnit/CN=localhost"
