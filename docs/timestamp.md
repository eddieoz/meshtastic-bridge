# Timestamp Plugin

## Overview

The Timestamp Plugin adds a timestamp field to packets as they flow through the Meshtastic Bridge pipeline. This enables time-based tracking, logging, and analysis of messages for debugging, monitoring, and record-keeping purposes.

## Quick Start

**Basic Usage:**
```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix
        field: timestamp
```

**Result:** Adds `"timestamp": 1706123456` to each packet.

## How It Works

The plugin operates as a pipeline processor that:

1. **Intercepts packets** as they flow through the pipeline
2. **Generates a timestamp** in the specified format
3. **Adds the timestamp** to the packet at the top level
4. **Passes the packet** to the next plugin in the pipeline

### Processing Flow

```
┌─────────────────────────────────────────────────┐
│  Incoming Packet                                 │
│  {                                               │
│    "from": "123456",                             │
│    "decoded": {"text": "Hello"}                  │
│  }                                               │
│           ↓                                      │
│  Timestamp Plugin                                │
│           ↓                                      │
│  Outgoing Packet                                 │
│  {                                               │
│    "from": "123456",                             │
│    "decoded": {"text": "Hello"},                 │
│    "timestamp": 1706123456  ← Added              │
│  }                                               │
└─────────────────────────────────────────────────┘
```

## Configuration

### Basic Configuration

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix      # Timestamp format (optional)
        field: timestamp  # Field name (optional)
```

### Configuration Parameters

#### `format`

**Type:** String
**Default:** `unix`
**Options:** `unix`, `unix_ms`, `iso`, `iso_local`

Specifies the timestamp format to use.

**Available Formats:**

##### `unix` (Default)
Unix epoch timestamp in seconds (integer).

**Example:** `1706123456`

**Use cases:**
- Most compact format
- Easy arithmetic (calculate time differences)
- Standard for many APIs and databases
- Compatible with most programming languages

##### `unix_ms`
Unix epoch timestamp in milliseconds (integer).

**Example:** `1706123456789`

**Use cases:**
- Higher precision (millisecond accuracy)
- Required by some APIs (JavaScript Date, some databases)
- Better for high-frequency event tracking

##### `iso`
ISO 8601 format in UTC timezone with 'Z' suffix.

**Example:** `2025-01-20T15:30:45.123456Z`

**Use cases:**
- Human-readable timestamps
- Standardized format (ISO 8601)
- No timezone confusion (always UTC)
- Better for logs and debugging

##### `iso_local`
ISO 8601 format in local system timezone.

**Example:** `2025-01-20T10:30:45.123456`

**Use cases:**
- Local time display
- Timezone-aware applications
- User-facing timestamps

#### `field`

**Type:** String
**Default:** `timestamp`

The name of the field to add to the packet.

**Examples:**
- `timestamp` (default)
- `received_at`
- `bridge_time`
- `processed_time`

**Use cases:**
- Distinguish multiple timestamps (e.g., `received_at` vs `sent_at`)
- Match naming conventions of downstream systems
- Avoid conflicts with existing fields

## Usage Examples

### Example 1: Basic Timestamp for MQTT

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix
        field: timestamp
    - mqtt_plugin:
        name: mqtt_broker
        topic: meshtastic/messages
```

**Result:** Each message published to MQTT includes a `timestamp` field.

**MQTT Payload:**
```json
{
  "from": "1234567890",
  "decoded": {
    "text": "Hello world"
  },
  "timestamp": 1706123456
}
```

### Example 2: High-Precision Timestamps

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix_ms
        field: received_at
    - mqtt_plugin:
        name: mqtt_broker
        topic: meshtastic/messages
```

**Use case:** Track message timing with millisecond precision for performance analysis.

**Result:**
```json
{
  "from": "1234567890",
  "decoded": {
    "text": "Hello"
  },
  "received_at": 1706123456789
}
```

### Example 3: Human-Readable Timestamps

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: iso
        field: bridge_time
    - mqtt_plugin:
        name: mqtt_broker
        topic: meshtastic/messages
```

**Use case:** Easy-to-read timestamps for debugging and log analysis.

**Result:**
```json
{
  "from": "1234567890",
  "decoded": {
    "text": "Hello"
  },
  "bridge_time": "2025-01-20T15:30:45.123456Z"
}
```

### Example 4: Multiple Timestamps

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix
        field: received_at
    - message_filter:
        from:
          allow:
            - "!abc123"
    - timestamp_plugin:
        format: unix
        field: processed_at
    - mqtt_plugin:
        name: mqtt_broker
        topic: meshtastic/messages
```

**Use case:** Track when message was received vs when it was processed (after filtering).

**Result:**
```json
{
  "from": "1234567890",
  "decoded": {
    "text": "Hello"
  },
  "received_at": 1706123456,
  "processed_at": 1706123457
}
```

### Example 5: Store & Forward with Timestamps

```yaml
pipelines:
  radio-to-mqtt:
    - store_forward_plugin:
        storage_path: ./store_forward.db
        device: radio1
    - timestamp_plugin:
        format: iso
        field: bridge_timestamp
    - mqtt_plugin:
        name: mqtt_broker
        topic: meshtastic/messages
```

**Use case:** Add bridge processing timestamp to distinguish from original message time.

## Common Use Cases

### 1. Message Logging

Track when messages arrive at the bridge for debugging and auditing.

```yaml
- timestamp_plugin:
    format: iso
    field: logged_at
```

### 2. Performance Monitoring

Measure pipeline processing time by adding timestamps at different stages.

```yaml
# Start of pipeline
- timestamp_plugin:
    format: unix_ms
    field: pipeline_start

# ... other plugins ...

# End of pipeline
- timestamp_plugin:
    format: unix_ms
    field: pipeline_end
```

Then calculate: `pipeline_end - pipeline_start = processing_time_ms`

### 3. Time-Series Data

Create time-series data for analytics and graphing.

```yaml
- timestamp_plugin:
    format: unix
    field: timestamp
- mqtt_plugin:
    name: influxdb
    topic: metrics/meshtastic
```

### 4. Message Ordering

Ensure messages can be ordered chronologically even if received out of order.

```yaml
- timestamp_plugin:
    format: unix_ms
    field: bridge_received_at
```

### 5. SLA Tracking

Track service-level agreement metrics for message delivery.

```yaml
- timestamp_plugin:
    format: unix
    field: received_at
- webhook:
    url: https://api.example.com/sla
```

## Logging

The plugin logs at different levels:

### Debug Level

```
DEBUG:meshtastic.bridge.plugin.timestamp:Added timestamp: timestamp=1706123456
```

Logs every timestamp addition (verbose).

### Warning Level

```
WARNING:meshtastic.bridge.plugin.timestamp:Unknown format type: custom, using unix
WARNING:meshtastic.bridge.plugin.timestamp:Packet is not a dict, cannot add timestamp
```

Logs configuration errors or unexpected packet formats.

### Enable Debug Logging

```yaml
- timestamp_plugin:
    format: unix
    field: timestamp
    log_level: debug
```

## Integration Examples

### With InfluxDB

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: unix
        field: time
    - mqtt_plugin:
        name: influxdb
        topic: meshtastic/metrics
```

### With Elasticsearch

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: iso
        field: "@timestamp"  # Elasticsearch standard field
    - webhook:
        url: https://elasticsearch.example.com/meshtastic/_doc
```

### With Webhooks

```yaml
pipelines:
  radio-to-mqtt:
    - timestamp_plugin:
        format: iso
        field: received_time
    - webhook:
        url: https://api.example.com/events
        body: |
          {
            "event": "meshtastic_message",
            "timestamp": "{received_time}",
            "message": "{MSG}"
          }
```

## Best Practices

### 1. Choose the Right Format

- **Unix timestamps**: For databases, arithmetic, storage efficiency
- **ISO timestamps**: For logs, debugging, human readability
- **Unix milliseconds**: For high-precision timing

### 2. Field Naming Conventions

Use descriptive field names:
- `received_at` - When bridge received the message
- `processed_at` - When processing completed
- `bridge_time` - Generic bridge timestamp
- `logged_at` - When message was logged

### 3. Pipeline Placement

Place timestamp plugin:
- **Early** - To track when messages arrive
- **Late** - To track when processing completes
- **Both** - To measure processing time

### 4. Timezone Considerations

- Use `iso` format (UTC) for distributed systems
- Use `iso_local` only for local display purposes
- Always document which timezone is used

### 5. Storage Efficiency

- Unix timestamps use less storage (integer vs string)
- ISO timestamps are larger but more readable
- Choose based on your storage/readability tradeoff

## Troubleshooting

### Timestamp Not Added

**Problem:** Packet doesn't have timestamp field.

**Possible causes:**
1. Plugin not in pipeline
2. Packet is not a dictionary
3. Plugin placed after a filter that drops the packet

**Solution:**
- Check pipeline configuration
- Verify packet format with debugger plugin
- Move timestamp plugin earlier in pipeline

### Wrong Timestamp Format

**Problem:** Timestamp in unexpected format.

**Possible causes:**
1. Wrong `format` configuration
2. Typo in format name
3. Default format being used

**Solution:**
```yaml
- timestamp_plugin:
    format: iso  # Check this value
    field: timestamp
    log_level: debug  # Enable logging
```

### Timestamp Overwrites Existing Field

**Problem:** Plugin overwrites an existing timestamp field.

**Solution:** Use a different field name:
```yaml
- timestamp_plugin:
    format: unix
    field: bridge_timestamp  # Different from existing 'timestamp'
```

### Timezone Issues

**Problem:** Timestamps don't match expected timezone.

**Solution:**
- Use `iso` format (UTC) for consistency
- Or use `iso_local` and document system timezone
- Avoid mixing `iso` and `iso_local` in same system

## Performance Considerations

### Overhead

The timestamp plugin has minimal overhead:
- **CPU**: Negligible (just gets current time)
- **Memory**: Adds ~4-8 bytes (unix) or ~25-30 bytes (ISO) per packet
- **Latency**: < 1 millisecond

### High-Volume Networks

For networks with 1000+ messages/second:
- Unix format is most efficient
- Consider using unix_ms only if millisecond precision is required
- ISO formats add string parsing overhead

### Batch Processing

The plugin processes packets individually (no batching). For batch scenarios, consider adding timestamps at the collection point instead.

## FAQ

**Q: Can I add multiple timestamps to one packet?**
A: Yes, add multiple timestamp plugins with different field names:
```yaml
- timestamp_plugin:
    field: received_at
- timestamp_plugin:
    field: processed_at
```

**Q: What timezone is used?**
A:
- `unix` and `unix_ms`: No timezone (epoch time)
- `iso`: UTC timezone (with 'Z' suffix)
- `iso_local`: System local timezone

**Q: Can I customize the timestamp format?**
A: No, only the four built-in formats are supported. For custom formats, use a webhook or external processor.

**Q: Does it use the packet's original time or bridge time?**
A: Bridge time. The plugin generates a new timestamp when the packet reaches it in the pipeline.

**Q: What happens if packet is not a dict?**
A: The plugin logs a warning and returns the packet unchanged.

**Q: Can I use this for message ordering?**
A: Yes, especially with `unix_ms` format for high precision. However, note this is bridge time, not original send time.

**Q: How accurate are the timestamps?**
A:
- `unix`: 1 second accuracy
- `unix_ms`: 1 millisecond accuracy
- `iso` and `iso_local`: Microsecond accuracy (but displayed to microseconds)

## Related Plugins

- **Store & Forward Plugin**: Uses timestamps internally for TTL and cleanup
- **Debugger Plugin**: Shows timestamps in debug logs
- **MQTT Plugin**: Can publish timestamped messages
- **Webhook Plugin**: Can include timestamps in API calls

## Version History

- **v1.0**: Initial implementation
  - Four timestamp formats (unix, unix_ms, iso, iso_local)
  - Configurable field name
  - Warning on invalid format
