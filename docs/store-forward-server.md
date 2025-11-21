# Store & Forward Server Plugin

## Quick Start

**TL;DR:**
1. Configure the plugin with your node IDs in `to.allow` list
2. When you come back online, send `!get` command
3. Receive all missed messages with sender and timestamp

**Example received message:**
```
[Stored Message]
From: !7f0f5719
Sent: 2025-01-20 22:15:32
Channel: 0
---
Hey, are you there?
```

## Overview

The Store & Forward plugin enables the Meshtastic Bridge to act as a message relay server, storing messages destined for nodes that are currently out of range or offline, and automatically delivering them when those nodes send the `!get` command.

### Aggressive Mode

This plugin operates in **"aggressive mode"**, which means it stores **ALL directed messages** regardless of whether the destination node appears online or offline. This ensures zero message loss in scenarios where nodes are:

- Out of radio range but recently active
- Intermittently connected (solar-powered, mobile devices)
- Moving in and out of coverage areas
- Operating in sparse mesh networks with unreliable connectivity

## Why Use Store & Forward?

### Problem It Solves

In a typical Meshtastic scenario, if you're hiking with a mobile radio and send a message from far away:
1. Your message may reach the mesh network via relay nodes
2. People receive your message and send replies
3. Your base station bridge receives the replies
4. **BUT** you're out of range and never receive the replies
5. Messages are lost forever ❌

### Solution

With the Store & Forward plugin:
1. Your message reaches the mesh via relays ✅
2. People send replies to you
3. Bridge receives replies and **stores them in database** ✅
4. You're out of range, but messages are safely queued
5. When you return to range, **send `!get` command**
6. **Bridge delivers all stored messages with metadata** ✅
7. You receive all replies with sender and timestamp info! 🎉

## How It Works

### Aggressive Mode Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  1. Message Arrives at Bridge                                │
│     ↓                                                        │
│  2. Check if Deliverable                                     │
│     ├─ TEXT_MESSAGE_APP ✓                                    │
│     └─ Other types (TELEMETRY, NODEINFO, POSITION, etc.) ✗  │
│     ↓                                                        │
│  3. Store in SQLite Database                                 │
│     ├─ Store for each node in allow list (if broadcast)      │
│     ├─ Don't store messages from bridge itself               │
│     └─ Apply from/to filters                                 │
│     ↓                                                        │
│  4. Attempt Immediate Delivery                               │
│     ├─ If destination recently seen → Try to send now        │
│     └─ Keep in queue regardless (may be out of range)        │
│     ↓                                                        │
│  5. When Node Sends "!get" Command                           │
│     ↓                                                        │
│  6. Bridge Triggers Delivery                                 │
│     ↓                                                        │
│  7. Deliver ALL Queued Messages (FIFO order)                 │
│     ├─ Exclude messages node itself sent                     │
│     ├─ Add metadata (from, timestamp, channel)               │
│     └─ Rate-limited (1 msg/sec)                              │
│     ↓                                                        │
│  8. Mark as Delivered (keep for 2hr grace period)            │
│     ↓                                                        │
│  9. Cleanup                                                  │
│     ├─ Delivered messages after 2 hours                      │
│     └─ Undelivered messages after 48 hours                   │
└─────────────────────────────────────────────────────────────┘
```

### Command-Based Delivery Trigger

**The `!get` Command:**

To retrieve stored messages, send the text `!get` on your Meshtastic channel:

1. **Type `!get`** in your Meshtastic app (channel message or DM to bridge)
2. **Send the message** - bridge detects the command
3. **Bridge delivers** all your stored messages automatically
4. **Receive messages** with metadata showing sender and timestamp

**Why command-based?**
- Works with infrastructure nodes (which can't receive DMs)
- Explicit user control - retrieve messages when you want them
- Simple and reliable - just send `!get`

**Message Format:**

When you receive stored messages, they include metadata:
```
[Stored Message]
From: !7f0f5719
Sent: 2025-01-20 22:15:32
Channel: 0
---
Original message content here
```

### Two-Tier Cleanup Strategy

**Tier 1: Delivered Messages**
- Kept for 2 hours (configurable grace period)
- Allows retry if initial delivery was marginal
- Then deleted to save space

**Tier 2: Undelivered Messages**
- Kept for 48 hours (configurable TTL)
- Long enough to catch offline/mobile nodes
- Eventually cleaned up if node never returns

## Installation & Setup

### 1. Prerequisites

The plugin is built into the bridge - no additional installation required. Just ensure you have:

- Meshtastic Bridge running
- Python 3.7+ (for SQLite support)
- Write access to storage directory

### 2. Configuration

Edit your `config.yaml` and add the store & forward plugin to your pipeline:

```yaml
devices:
  - name: t_echo
    serial: /dev/ttyACM0

mqtt_servers:
  - name: external
    server: 192.168.0.120
    port: 1883
    topic: meshtastic/radio

pipelines:
  radio-to-mqtt:
    # Store & Forward Plugin (must be before message_filter)
    - store_forward_plugin:
        storage_path: ./data/store_forward.db
        device: t_echo
        ttl_hours: 48
        delivered_retention_hours: 2
        max_messages_per_node: 500
        offline_threshold_minutes: 30
        log_level: info
        store_broadcasts: true  # Store broadcast messages
        to:
          allow:  # Only store messages for these nodes
            - "1119572084"   # Your mobile radio
            - "2131711769"   # Another node

    - message_filter:
        from:
          disallow:
            - "!5af47b5e"  # Filter bridge's own messages

    - timestamp_plugin:
        format: unix
        field: timestamp

    - mqtt_plugin:
        name: external
        topic: meshtastic/radio
```

### 3. Create Storage Directory (if using /data)

```bash
# If using /data/store_forward.db
sudo mkdir -p /data
sudo chown $USER:$USER /data

# Or use local directory
mkdir -p ./data
```

### 4. Start the Bridge

```bash
python main.py
```

## Configuration Reference

### Required Parameters

#### `storage_path`

**Type:** String
**Required:** Yes
**Example:** `./store_forward.db` or `/data/store_forward.db`

Path to the SQLite database file for storing messages. The database will be created automatically if it doesn't exist.

**Recommendations:**
- Use absolute path for production: `/data/store_forward.db`
- Use relative path for testing: `./store_forward.db`
- Ensure directory has write permissions
- Use SSD for better performance with high message volume

#### `device`

**Type:** String
**Required:** Yes
**Example:** `t_echo`

Name of the Meshtastic device to use for sending stored messages. Must match a device name in the `devices` section.

### Optional Parameters

#### `ttl_hours`

**Type:** Integer
**Default:** `48`
**Example:** `ttl_hours: 72`

Time-to-live in hours for **undelivered messages**. Messages older than this will be automatically deleted during cleanup.

**Recommendations:**
- **24 hours**: For high-traffic networks with good connectivity
- **48 hours**: Default - good balance for most use cases
- **72-168 hours**: For sparse networks or nodes that check in weekly

#### `delivered_retention_hours`

**Type:** Integer
**Default:** `2`
**Example:** `delivered_retention_hours: 4`

How long to keep **delivered messages** in the database before deleting them. This grace period allows for retry if the initial delivery was marginal (e.g., weak signal).

**Recommendations:**
- **1-2 hours**: Default - allows retry for marginal connections
- **4-6 hours**: If you have very unreliable radio links
- **0.5 hours**: For high-volume networks where storage is limited

#### `max_messages_per_node`

**Type:** Integer
**Default:** `500`
**Example:** `max_messages_per_node: 1000`

Maximum number of **undelivered messages** to store per destination node. When this limit is reached, the oldest messages are deleted first.

**Recommendations:**
- **100-200**: Low-traffic networks
- **500**: Default - good for most scenarios (aggressive mode)
- **1000+**: High-traffic networks with lots of mobile nodes

#### `offline_threshold_minutes`

**Type:** Integer
**Default:** `30`
**Example:** `offline_threshold_minutes: 60`

Number of minutes without activity before considering a node "not recently seen". Used for immediate delivery attempts.

**How it works:**
- If node was seen within this threshold → Attempt immediate delivery
- Otherwise → Only queue for later delivery

**Recommendations:**
- **15-30 minutes**: Active networks with frequent position beacons
- **60 minutes**: Networks with less frequent updates
- **Does not affect queued delivery** - just optimizes for low latency

#### `log_level`

**Type:** String
**Default:** `info`
**Options:** `debug`, `info`, `warning`, `error`
**Example:** `log_level: debug`

Logging verbosity for the plugin.

**Levels:**
- **`debug`**: Detailed packet processing, node presence updates, database operations
- **`info`**: Message storage, delivery events, cleanup operations (recommended)
- **`warning`**: Message limit exceeded, delivery failures
- **`error`**: Database errors, configuration errors

#### `store_broadcasts`

**Type:** Boolean
**Default:** `false`
**Example:** `store_broadcasts: true`

Enable storage of broadcast/channel messages in addition to direct messages. When enabled, broadcast messages are stored individually for each node in the `to.allow` list.

**Recommendations:**
- **`true`**: Store both broadcasts and direct messages (comprehensive coverage)
- **`false`**: Store only direct messages (reduces storage usage)

#### `to.allow`

**Type:** List of strings
**Required:** No (but highly recommended)
**Example:**
```yaml
to:
  allow:
    - "1119572084"
    - "2131711769"
```

Whitelist of node IDs to store messages for. Only messages destined for these nodes will be stored and delivered.

**Benefits:**
- Reduces storage usage by filtering unnecessary messages
- Focuses on specific mobile nodes that need store & forward
- Nodes receive only messages from others (not their own)

**Format:** Node IDs as strings (decimal format)

## Usage Examples

### Example 1: Basic Setup for Home Base Station

```yaml
pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        storage_path: ./store_forward.db
        device: home_radio
        ttl_hours: 48
        log_level: info
        store_broadcasts: true
        to:
          allow:
            - "1234567890"  # Your mobile radio
    - mqtt_plugin:
        name: mqtt_broker
        topic: mesh/messages
```

**Use Case:** Simple home setup with one mobile radio that checks in daily.

**How to use:**
1. Leave mobile radio at home (in range)
2. Go hiking with handheld radio
3. When you return, send `!get` command from mobile radio
4. Receive all missed messages with metadata

### Example 2: High-Volume Network

```yaml
pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        storage_path: /data/store_forward.db
        device: base_station
        ttl_hours: 24
        delivered_retention_hours: 1
        max_messages_per_node: 200
        offline_threshold_minutes: 15
        log_level: info
```

**Use Case:** Busy network with many nodes, shorter retention to save storage.

### Example 3: Sparse Network with Weekly Check-ins

```yaml
pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        storage_path: /mnt/ssd/store_forward.db
        device: remote_relay
        ttl_hours: 168  # 1 week
        delivered_retention_hours: 4
        max_messages_per_node: 1000
        offline_threshold_minutes: 120
        log_level: info
```

**Use Case:** Remote area where nodes may only check in once a week.

### Example 4: Debug Mode

```yaml
pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        storage_path: ./debug_store_forward.db
        device: test_radio
        ttl_hours: 2  # Short TTL for testing
        delivered_retention_hours: 0.5
        max_messages_per_node: 50
        log_level: debug  # Verbose logging
```

**Use Case:** Testing and debugging the plugin behavior.

## Monitoring

### Log Messages

**Initialization:**
```
INFO:meshtastic.bridge.plugin.store_forward:Store & Forward plugin initialized (Aggressive Mode)
INFO:meshtastic.bridge.plugin.store_forward:Storage: /data/store_forward.db
INFO:meshtastic.bridge.plugin.store_forward:TTL: 48h, Grace period: 2h
INFO:meshtastic.bridge.plugin.store_forward:Max messages per node: 500
INFO:meshtastic.bridge.plugin.store_forward:Database initialized: 12 undelivered messages, 5 tracked nodes
```

**Message Storage:**
```
INFO:meshtastic.bridge.plugin.store_forward:Stored message 42: 123456 → 999999
```

**Message Delivery:**
```
INFO:meshtastic.bridge.plugin.store_forward:Delivering 3 stored messages to node 999999
INFO:meshtastic.bridge.plugin.store_forward:Delivered message 42 to 999999 from 123456
INFO:meshtastic.bridge.plugin.store_forward:Delivered message 43 to 999999 from 123456
INFO:meshtastic.bridge.plugin.store_forward:Delivered message 44 to 999999 from 789012
INFO:meshtastic.bridge.plugin.store_forward:Delivered 3/3 messages to 999999
```

**Cleanup:**
```
INFO:meshtastic.bridge.plugin.store_forward:Cleanup: removed 5 delivered messages (past grace period), 2 undelivered messages (past TTL)
```

**Warnings:**
```
WARNING:meshtastic.bridge.plugin.store_forward:Enforced message limit for node 999999: removed 10 oldest messages
WARNING:meshtastic.bridge.plugin.store_forward:Failed to deliver message 42 to 999999
```

### Database Queries

Check database stats:

```bash
# Undelivered messages
sqlite3 /data/store_forward.db "SELECT COUNT(*) FROM messages WHERE delivered=0"

# Delivered messages (in grace period)
sqlite3 /data/store_forward.db "SELECT COUNT(*) FROM messages WHERE delivered=1"

# Tracked nodes
sqlite3 /data/store_forward.db "SELECT COUNT(*) FROM node_presence"

# Messages per node
sqlite3 /data/store_forward.db "
  SELECT to_node, COUNT(*) as count
  FROM messages
  WHERE delivered=0
  GROUP BY to_node
  ORDER BY count DESC
"

# Oldest undelivered message
sqlite3 /data/store_forward.db "
  SELECT datetime(created_at, 'unixepoch'), to_node, from_node
  FROM messages
  WHERE delivered=0
  ORDER BY created_at ASC
  LIMIT 1
"

# Node presence
sqlite3 /data/store_forward.db "
  SELECT node_id, datetime(last_seen, 'unixepoch'), status
  FROM node_presence
  ORDER BY last_seen DESC
"
```

### Database Size Monitoring

```bash
# Check database file size
ls -lh /data/store_forward.db

# Check number of messages and storage usage
sqlite3 /data/store_forward.db "
  SELECT
    COUNT(*) as total_messages,
    SUM(CASE WHEN delivered=0 THEN 1 ELSE 0 END) as undelivered,
    SUM(CASE WHEN delivered=1 THEN 1 ELSE 0 END) as delivered,
    ROUND(SUM(LENGTH(packet_json))/1024.0/1024.0, 2) as data_mb
  FROM messages
"
```

## Troubleshooting

### Messages Not Being Stored

**Check:**
1. Is the plugin in the pipeline? (Check `config.yaml`)
2. Are messages directed (not broadcasts)? Broadcasts are skipped
3. Is storage path writable? Check permissions
4. Check logs for errors: `grep store_forward main.log`

**Debug:**
```yaml
store_forward_plugin:
  log_level: debug  # Enable verbose logging
```

### Messages Not Being Delivered

**Check:**
1. Is the device reference correct? (Check `device:` parameter)
2. Is the destination node actually coming online? (Check `node_presence` table)
3. Are messages expired? (Check `expires_at` timestamp)
4. Check logs for delivery attempts and failures

**Debug:**
```bash
# Check if node has undelivered messages
sqlite3 /data/store_forward.db "SELECT * FROM messages WHERE to_node='999999' AND delivered=0"

# Check when node was last seen
sqlite3 /data/store_forward.db "SELECT datetime(last_seen, 'unixepoch') FROM node_presence WHERE node_id='999999'"
```

### Database Growing Too Large

**Solutions:**
1. Reduce `ttl_hours` (e.g., from 48 to 24)
2. Reduce `delivered_retention_hours` (e.g., from 2 to 1)
3. Reduce `max_messages_per_node` (e.g., from 500 to 200)
4. Manually clean up old messages:

```bash
# Delete all delivered messages
sqlite3 /data/store_forward.db "DELETE FROM messages WHERE delivered=1"

# Delete messages older than 7 days
sqlite3 /data/store_forward.db "DELETE FROM messages WHERE created_at < strftime('%s', 'now', '-7 days')"

# Vacuum to reclaim space
sqlite3 /data/store_forward.db "VACUUM"
```

### Device Not Found Warning

```
WARNING:meshtastic.bridge.plugin.store_forward:Device 't_echo' not found. Store & forward may not function correctly.
```

**Solution:** Ensure `device:` parameter matches a device name in your `devices:` section:

```yaml
devices:
  - name: t_echo  # This name must match
    serial: /dev/ttyACM0

pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        device: t_echo  # Must match device name above
```

### High CPU Usage

If you notice high CPU usage during cleanup:

**Solutions:**
1. Increase cleanup interval (modify code to run every 200 packets instead of 100)
2. Reduce message volume (lower `max_messages_per_node`)
3. Use SSD instead of SD card for storage

### Permission Denied Errors

```
ERROR:meshtastic.bridge.plugin.store_forward:Failed to initialize database: unable to open database file
```

**Solution:**
```bash
# Ensure directory exists and is writable
mkdir -p /data
sudo chown $USER:$USER /data

# Or use local directory
mkdir -p ./data
```

## Performance Considerations

### Storage Requirements

**Typical message size:** ~500-1000 bytes (JSON serialized)

**Example calculations:**
- 100 messages = ~50-100 KB
- 1,000 messages = ~500 KB - 1 MB
- 10,000 messages = ~5-10 MB

**With default settings (500 msgs/node, 48hr TTL):**
- 10 nodes = ~2.5-5 MB
- 50 nodes = ~12-25 MB
- 100 nodes = ~25-50 MB

### Rate Limiting

The plugin rate-limits message delivery to **1 message per second** to avoid flooding the mesh network. This means:

- 10 queued messages = 10 seconds to deliver
- 50 queued messages = 50 seconds to deliver
- 100 queued messages = ~1.7 minutes to deliver

### Cleanup Performance

Cleanup runs **every 100 packets** processed. On a typical network:
- Low traffic: Cleanup every few minutes
- Medium traffic: Cleanup every minute
- High traffic: Cleanup every 10-30 seconds

## Limitations

1. **No ACK tracking**: Messages are marked "delivered" when sent to the radio, but there's no confirmation the destination node actually received them

2. **Possible duplicate delivery**: If a node is marginally in range, it may receive messages both from immediate delivery and queued delivery

3. **Local storage only**: Messages are stored only on the bridge running the plugin, not distributed across the mesh

4. **Passive presence detection**: The plugin can only detect nodes when they send packets - it cannot actively query node status

5. **No message priority**: All messages are treated equally (FIFO delivery)

## Security Considerations

1. **No encryption**: Messages are stored in plaintext in the SQLite database
   - Recommendation: Use filesystem encryption if storing sensitive messages

2. **No authentication**: Any node can send messages to any other node
   - This matches Meshtastic's trust model

3. **Storage quota**: Configure `max_messages_per_node` to prevent storage exhaustion attacks

## Advanced Usage

### Custom Storage Location

For better performance or reliability:

```yaml
store_forward_plugin:
  storage_path: /mnt/ssd/meshtastic/store_forward.db  # SSD for speed
  # or
  storage_path: /mnt/raid/meshtastic/store_forward.db  # RAID for reliability
```

### Multiple Bridges

If running multiple bridges, each should have its own database:

```yaml
# Bridge 1
store_forward_plugin:
  storage_path: /data/bridge1_store_forward.db
  device: radio1

# Bridge 2
store_forward_plugin:
  storage_path: /data/bridge2_store_forward.db
  device: radio2
```

### Backup and Recovery

Backup the database periodically:

```bash
# Backup
cp /data/store_forward.db /backups/store_forward_$(date +%Y%m%d).db

# Or use SQLite backup command
sqlite3 /data/store_forward.db ".backup /backups/store_forward_$(date +%Y%m%d).db"

# Restore
cp /backups/store_forward_20250120.db /data/store_forward.db
# Restart bridge
```

## FAQ

**Q: Will this work with encrypted messages?**
A: Yes, the plugin stores the entire packet including encrypted payloads. Messages will be delivered encrypted and decrypted by the receiving node.

**Q: Can I use this with the mqtt-to-radio pipeline?**
A: The plugin is designed for radio-to-mqtt pipelines. For mqtt-to-radio, messages would need additional handling (not currently implemented).

**Q: What happens if the bridge crashes?**
A: All stored messages persist in the SQLite database and will be available when the bridge restarts.

**Q: How do I retrieve my stored messages?**
A: Send `!get` command on your Meshtastic channel. The bridge will detect it and deliver all your stored messages with metadata (sender, timestamp, channel).

**Q: How do I reset/clear all stored messages?**
A: Delete or rename the database file, then restart the bridge. A new empty database will be created.

```bash
# Clear all data
rm /data/store_forward.db
# Restart bridge
python main.py
```

**Q: Does this replace Meshtastic's built-in store & forward?**
A: No, this is complementary. This works at the bridge level (MQTT/network side), while Meshtastic's built-in S&F works at the device/mesh level.

**Q: Will I receive my own messages back?**
A: No. The plugin automatically excludes messages you sent when delivering stored messages. You only receive messages from other nodes.

**Q: Does it work with broadcast/channel messages?**
A: Yes, if you enable `store_broadcasts: true` in the configuration. Broadcast messages are stored individually for each node in your allow list.

**Q: What message types are stored?**
A: Currently only TEXT_MESSAGE_APP packets are stored and delivered. Position, telemetry, and other packet types are not stored to optimize storage usage.

**Q: Can I filter which nodes to track?**
A: Yes, use the `to.allow` configuration to specify which nodes should have messages stored. This reduces storage usage and focuses on nodes that need store & forward.

## Support

For issues, questions, or feature requests:
- GitHub Issues: [meshtastic-bridge issues](https://github.com/gwhittington/meshtastic-bridge/issues)
- Meshtastic Discord: [discord.gg/meshtastic](https://discord.gg/meshtastic)

## Version History

- **v1.1** (2025-01): Enhanced filtering and metadata
  - Command-based delivery trigger (`!get` command)
  - Message metadata (sender, timestamp, channel)
  - Exclude own messages from delivery
  - Only store deliverable packet types (TEXT_MESSAGE_APP)
  - Broadcast message support with per-node storage
  - Node filtering with allow/disallow lists
  - Improved storage efficiency

- **v1.0** (2025-01): Initial aggressive mode implementation
  - Store all directed messages
  - Two-tier cleanup (delivered + TTL)
  - Immediate delivery attempts
  - SQLite persistence
