import logging
import logging.handlers
import pickle
import socketserver
import struct

logger1 = logging.getLogger(__name__)

# Define the log handler that processes incoming log records
class LogRecordStreamHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Receive the data in the size of a struct (4 bytes)
        while True:
            logger1.error("listening")
            try:
                # First 4 bytes are the length of the incoming message
                chunk = self.connection.recv(4)
                if len(chunk) < 4:
                    break
                slen = struct.unpack(">L", chunk)[0]
                data = self.connection.recv(slen)
                print(data)
                record = pickle.loads(data)
                # Use the log record on the server-side logger
                print(record)
                # logger = logging.getLogger(record.name)
                # print(record)
                # logger.handle(record)  # Pass the record to the logger
            except Exception as e:
                logger1.error("listening")
                print(f"Error: {e}")
                break


# Define the log server using TCP
class LogRecordSocketReceiver(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, host="0.0.0.0", port=5141):
        socketserver.ThreadingTCPServer.__init__(
            self, (host, port), LogRecordStreamHandler
        )


# Set up the server-side logger
# logging.basicConfig(
#     level=logging.DEBUG,
#     format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
#     handlers=[logging.FileHandler("aggregated_logs.log"), logging.StreamHandler()],
# )

# Start the log receiver server
if __name__ == "__main__":
    logger1.error("Starting log receiver on port 5141...")
    tcp_server = LogRecordSocketReceiver()
    print("Starting log receiver on port 5141...")
    tcp_server.serve_forever()
