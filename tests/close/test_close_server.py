# This scripts simulates unclean shutdowns of a websocket server.

import os
import asyncio
import socket
import sys
import websockets
from websockets.server import WebSocketServerProtocol
import ssl
import logging

logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

class CustomWebSocketServerProtocol(WebSocketServerProtocol):
    async def send_invalid_frame(self):
        # Create an invalid frame (this example uses an undefined opcode)
        invalid_frame = b'\x0c\x00'  # Opcode 0xC is undefined
        
        # Send the invalid frame directly, bypassing websockets' frame handling
        self.transport.write(invalid_frame)

async def wss_server(websocket, path):
    global close_mode
    print("Server started. Close mode: ", close_mode)

    message = await websocket.recv()
    print(f"Received message: {message}")
    
    await websocket.send(f"About to close the server...")

    if close_mode == "sys_exit":
        sys.exit(1)  # close the server
    elif close_mode == "socket_shutdown":
        # get the underlying transport and socket
        transport = websocket.transport
        raw_socket = transport.get_extra_info("socket")
        # simulate an unclean shutdown by closing the socket directly
        raw_socket.shutdown(socket.SHUT_RDWR)
        raw_socket.close()
        await asyncio.sleep(2)
    elif close_mode == "server_close":
        await websocket.close()
        await asyncio.sleep(2)
    elif close_mode == "transport_close":
        websocket.transport.close()
        await asyncio.sleep(2)
    elif close_mode == "invalid_frame":
        await websocket.send_invalid_frame()
        await asyncio.sleep(2)
    else:
        print("Invalid close mode: ", close_mode)
        sys.exit(1)


if __name__ == "__main__":
    # close_mode = "sys_exit" # causes async_shutdown to block indefinitely
    # close_mode = "socket_shutdown" # causes broken pipe
    # close_mode = "server_close"  # proper shutdown of the server
    # close_mode = "transport_close"  # close the transport directly
    close_mode = sys.argv[1]

    if not close_mode:
        print("Please provide a close mode.")
        sys.exit(1)
    
    print("Close mode: ", close_mode)

    # set up SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        os.path.join(os.path.dirname(__file__), "../certs/cert.pem"),
        os.path.join(os.path.dirname(__file__), "../certs/key.pem"),
    )

    start_server = websockets.serve(
        wss_server,
        "localhost",
        9443,
        ping_interval=5,
        ssl=ssl_context,
        logger=logging.getLogger("websockets.server"),
        create_protocol=CustomWebSocketServerProtocol
    )

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()
