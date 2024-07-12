import asyncio
import websockets
import logging

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

async def send_ping(websocket, path):
    i = 1
    while True:
        try:
            await websocket.send(f"This is message #{i}")
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
    8080,
    ping_interval=5,
    logger=logging.getLogger("websockets.server"),
    # compression=None
)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
