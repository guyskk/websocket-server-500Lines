# WebSocket server 500 Lines

WebSocket chat server using only Python standard library, less than 500 lines.

1. (TCP) echo server 
2. (HTTP) http server 
3. (WebSocket) websocket server


## WebSocket’s weakness

1. Difficult to establish connection cross proxy and firewall
2. No Auto-reconnection when connection failed / disconnected
3. No Heartbeat detection / Disconnection detection
4. No Namespace/Topic/Room/Channel features
5. Message acknowledgement and retransmission


## Alternatives

1. Long/short polling (Poor performance)
2. Server-sent Events (One-way communication)
3. Socket.IO


## Socket.IO

- https://socket.io/docs/#What-Socket-IO-is
- https://github.com/socketio/engine.io#transports

```
+------------------------------------------------------------+
|                     Socket.IO protocol                     |
+-------------------------------+----------------------------+
| XHR / JSONP polling transport |     WebSocket transport    |
+-------------------------------+----------------------------+
```
