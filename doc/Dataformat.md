# Dataformat

## Message

Used to communicate with your friends.<br>
This chain is considered as not protected.

### Sent to MQTT server

A message sent to a MQTT server should be a byte-stream looks like:

```text
+++++++++++
| iv | E(m, k) |
+++++++++++
```

### Plaintext message

Plaintext message "m" is a JSON string with following keys.

```json
{
	"version": 2,
	"msg": "Hello world!",
	"type": 0,
	"time": 114514,
	"option": null
}
```

## Controller

Used to communicate with henChat server (Hakkenki).<br>
This chain is protected by TLS.

### 1. A new room is established by client A

From A's client, it will send following message to server.

```json
{
	"type": 0,
	"wcc": "9b283e6c...",  // WC code, sent by untrustable channels
	"max_client": 2,
	"timeout": 114514
}
```

### 2. Server replies to A

If the new room is established, A will receive this:

```json
{
	"type": 0,
	"svc": "e482da11...",
	"timeout": 114514
}
```

If failed, the message will be:

```json
{
	"type": -1,
	"code": 0,
	"msg": "SVC assignment failed."
}
```

### 3. Client B enters the room

With WCC and CH sent by A, B enters the room, and automatically send message to server:

```json
{
	"type": 1,
	"wcc": "9b283e6c..."
}
```

### 4. Server replies to B

If all is OK, B will receive this:

```json
{
	"type": 1,
	"svc": "e482da11...",
	"timeout": 114514
}
```

If failed, the message will be:

```json
{
	"type": -1,
	"code": 1,
	"msg": "No such a room for you."
}
```

### 5. SVC update

Once SVC get timeouted, clients should send following message to server:

```json
{
	"type": 2,
	"svc": "e482da11..."
}
```

And get reply:

```json
{
	"type": 2,
	"svc": "961dc2a0..."
}
```

Or:

```json
{
	"type": -1,
	"code": 1,
	"msg": "No such a room for you."
}
```