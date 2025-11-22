from haversine import haversine
from meshtastic import mesh_pb2
from random import randrange
import base64
import json
import logging
import os
import re
import sqlite3
import ssl
import time

plugins = {}


class Plugin(object):
    def __init__(self) -> None:
        self.logger.setLevel(logging.INFO)

    def configure(self, devices, mqtt_servers, config):
        self.config = config
        self.devices = devices
        self.mqtt_servers = mqtt_servers

        if config and "log_level" in config:
            if config["log_level"] == "debug":
                self.logger.setLevel(logging.DEBUG)
            elif config["log_level"] == "info":
                self.logger.setLevel(logging.INFO)

    def do_action(self, packet):
        pass


class PacketFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.packet")

    def strip_raw(self, data):
        if type(data) is not dict:
            return data

        if "raw" in data:
            del data["raw"]

        for k, v in data.items():
            data[k] = self.strip_raw(v)

        return data

    def normalize(self, dict_obj):
        """
        Packets are either a dict, string dict or string
        """
        if type(dict_obj) is not dict:
            try:
                dict_obj = json.loads(dict_obj)
            except:
                dict_obj = {"decoded": {"text": dict_obj}}

        return self.strip_raw(dict_obj)

    def do_action(self, packet):
        self.logger.debug(f"Before normalization: {packet}")
        packet = self.normalize(packet)

        if "decoded" in packet and "payload" in packet["decoded"]:
            if type(packet["decoded"]["payload"]) is bytes:
                text = packet["decoded"]["payload"]
                packet["decoded"]["payload"] = base64.b64encode(
                    packet["decoded"]["payload"]
                ).decode("utf-8")

        self.logger.debug(f"After normalization: {packet}")

        return packet


plugins["packet_filter"] = PacketFilter()


class DebugFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.logging")

    def do_action(self, packet):
        self.logger.debug(packet)
        return packet


plugins["debugger"] = DebugFilter()


class MessageFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.message")

    def do_action(self, packet):
        if not packet:
            self.logger.error("Missing packet")
            return packet

        # Skip filtering encrypted packets - they need to be decrypted first
        if "decoded" not in packet:
            self.logger.debug("Skipping filter for encrypted/undecoded packet")
            return packet

        text = packet["decoded"]["text"] if "text" in packet["decoded"] else None

        if text and "message" in self.config:
            if "allow" in self.config["message"]:
                matches = False
                for allow_regex in self.config["message"]["allow"]:
                    if not matches and re.search(allow_regex, text):
                        matches = True

                if not matches:
                    self.logger.debug(
                        f"Dropped because it doesn't match message allow filter"
                    )
                    return None

            if "disallow" in self.config["message"]:
                matches = False
                for disallow_regex in self.config["message"]["disallow"]:
                    if not matches and re.search(disallow_regex, text):
                        matches = True

                if matches:
                    self.logger.debug(
                        f"Dropped because it matches message disallow filter"
                    )
                    return None

        filters = {
            "app": packet["decoded"]["portnum"] if "portnum" in packet["decoded"] else None,
            "from": packet["fromId"] if "fromId" in packet else None,
            "to": packet["toId"] if "toId" in packet else None,
        }

        for filter_key, value in filters.items():
            if filter_key in self.config and value is not None:
                filter_val = self.config[filter_key]

                if (
                    "allow" in filter_val
                    and filter_val["allow"]
                    and value not in filter_val["allow"]
                ):
                    self.logger.debug(
                        f"Dropped because {value} doesn't match {filter_key} allow filter"
                    )
                    return None

                if (
                    "disallow" in filter_val
                    and filter_val["disallow"]
                    and value in filter_val["disallow"]
                ):
                    self.logger.debug(
                        f"Dropped because {value} matches {filter_key} disallow filter"
                    )
                    return None

        self.logger.debug(f"Accepted")
        return packet


plugins["message_filter"] = MessageFilter()


class LocationFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.distance")

    def do_action(self, packet):
        message_source_position = None
        current_local_position = None

        if "device" in self.config and self.config["device"] in self.devices:
            nodeInfo = self.devices[self.config["device"]].getMyNodeInfo()
            current_local_position = (
                nodeInfo["position"]["latitude"],
                nodeInfo["position"]["longitude"],
            )

        if (
            "decoded" in packet
            and "position" in packet["decoded"]
            and "latitude" in packet["decoded"]["position"]
            and "longitude" in packet["decoded"]["position"]
        ):
            message_source_position = (
                packet["decoded"]["position"]["latitude"],
                packet["decoded"]["position"]["longitude"],
            )

        if "compare_latitude" in self.config and "compare_longitude" in self.config:
            current_local_position = (
                self.config["compare_latitude"],
                self.config["compare_longitude"],
            )

        if message_source_position and current_local_position:
            distance_km = haversine(message_source_position, current_local_position)

            comparison = (
                self.config["comparison"] if "comparison" in self.config else "within"
            )

            # message originates from too far a distance
            if "max_distance_km" in self.config and self.config["max_distance_km"] > 0:
                acceptable_distance = self.config["max_distance_km"]

                if comparison == "within" and distance_km > acceptable_distance:
                    self.logger.debug(
                        f"Packet from too far: {distance_km} > {acceptable_distance}"
                    )
                    return None
                elif comparison == "outside" and distance_km < acceptable_distance:
                    self.logger.debug(
                        f"Packet too close: {distance_km} < {acceptable_distance}"
                    )
                    return None

        if "latitude" in self.config:
            packet["decoded"]["position"]["latitude"] = self.config["latitude"]
        if "longitude" in self.config:
            packet["decoded"]["position"]["longitude"] = self.config["longitude"]

        return packet


plugins["location_filter"] = LocationFilter()


class WebhookPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.webhook")

    def do_action(self, packet):
        if "active" in self.config and not self.config["active"]:
            return packet

        if "body" not in self.config:
            self.logger.warning("Missing config: body")
            return packet

        import requests

        position = (
            packet["decoded"]["position"] if "position" in packet["decoded"] else None
        )
        text = packet["decoded"]["text"] if "text" in packet["decoded"] else None

        macros = {
            "{LAT}": position["latitude"] if position else "",
            "{LNG}": position["longitude"] if position else "",
            "{MSG}": self.config["message"] if "message" in self.config else text,
            "{FID}": packet["fromId"],
            "{TID}": packet["toId"],
        }

        body = self.config["body"]

        for macro, value in macros.items():
            body = body.replace(macro, str(value))

        payload = json.loads(body)

        self.logger.debug(f"Sending http POST request to {self.config['url']}")

        # pass secrets from environment variables to request headers
        headers = self.config["headers"] if "headers" in self.config else {}
        for k, v in headers.items():
            for ek, ev in os.environ.items():
                needle = "{" + ek + "}"
                if needle in v:
                    v = v.replace(needle, ev)

            headers[k] = v

        response = requests.post(self.config["url"], headers=headers, json=payload)

        if not response.ok:
            self.logger.warning(f"Error returned: {response.status_code}")

        return packet


plugins["webhook"] = WebhookPlugin()


class MQTTPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.mqtt")

    def do_action(self, packet):
        required_options = ["name", "topic"]

        for option in required_options:
            if option not in self.config:
                self.logger.warning(f"Missing config: {option}")
                return packet

        if self.config["name"] not in self.mqtt_servers:
            self.logger.warning(f"No server established: {self.config['name']}")
            return packet

        mqtt_server = self.mqtt_servers[self.config["name"]]

        if not mqtt_server.is_connected():
            self.logger.error("Not sent, not connected")
            return

        packet_message = json.dumps(packet)

        if "message" in self.config:
            message = self.config["message"].replace("{MSG}", packet["decoded"]["text"])
        else:
            message = packet_message

        info = mqtt_server.publish(self.config["topic"], message)
        info.wait_for_publish()

        self.logger.debug("Message sent")

        return packet


plugins["mqtt_plugin"] = MQTTPlugin()


class OwntracksPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.Owntracks")

    def do_action(self, packet):

        required_options = ["tid_table", "server_name"]
        for option in required_options:
            if option not in self.config:
                self.logger.warning(f"Missing config: {option}")
                return packet
        #tid_table = self.config["tid_table"]
        tid_table = {}
        for tid_entry in self.config["tid_table"]: # We want to check for a key with an ! and convert to string
          if "!" in tid_entry:
              tid_table[str(int(tid_entry[1:], 16))] = self.config["tid_table"][tid_entry]
          else:
              tid_table[tid_entry] = self.config["tid_table"][tid_entry]

        if not "from" in packet:
            self.logger.warning("Missing from: field")
            return packet

        if packet["from"] < 0:
            packet["from"] = packet["from"] +(1 << 32)

        if not str(packet["from"]) in tid_table:
            self.logger.warning(f"Sender not in tid_table: {packet}")
            return packet

        from_str = str(packet["from"])

        message = json.loads('{"_type":"location", "bs":0}')
        message["tid"] = tid_table[from_str][1]
        self.logger.debug(f"processing packet {packet}")
        #Packet direct from radio
        if (
            "decoded" in packet
            and "position" in packet["decoded"]
            and "latitude" in packet["decoded"]["position"]
            and packet["decoded"]["position"]["latitude"] != 0
        ):
            message["lat"] = packet["decoded"]["position"]["latitude"]
            message["lon"] = packet["decoded"]["position"]["longitude"]
            message["tst"] = packet["decoded"]["position"]["time"]
            message["created_at"] = packet["rxTime"]
            if "altitude" in packet["decoded"]["position"]:
                message["alt"] = packet["decoded"]["position"]["altitude"]

        #packet from mqtt
        elif (
            "type" in packet
            and packet["type"] == "position"
            and "payload" in packet
            and "latitude_i" in packet["payload"]
            and packet["payload"]["latitude_i"] != 0
        ):
            message["lat"] = packet["payload"]["latitude_i"]/10000000
            message["lon"] = packet["payload"]["longitude_i"]/10000000
            message["tst"] = packet["timestamp"]
            if ("time" in packet["payload"]):
                message["created_at"] = packet["payload"]["time"]
            else:
                message["created_at"] = packet["timestamp"]
            if "altitude" in packet["payload"]:
                message["alt"] = packet["payload"]["altitude"]
        else:
            self.logger.debug("Not a location packet")
            return packet

        if self.config["server_name"] not in self.mqtt_servers:
            self.logger.warning(f"No server established: {self.config['server_name']}")
            return packet

        mqtt_server = self.mqtt_servers[self.config["server_name"]]

        if not mqtt_server.is_connected():
            self.logger.error("Not sent, not connected")
            return

        self.logger.debug("Sending owntracks message")

        info = mqtt_server.publish("owntracks/user/" + tid_table[from_str][0], json.dumps(message))
        #info.wait_for_publish()

        self.logger.debug("Message sent")

        return packet


plugins["owntracks_plugin"] = OwntracksPlugin()


class EncryptFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.encrypt")

    def do_action(self, packet):
        if "key" not in self.config:
            return None

        from jwcrypto import jwk, jwe
        from jwcrypto.common import json_encode, json_decode

        with open(self.config["key"], "rb") as pemfile:
            encrypt_key = jwk.JWK.from_pem(pemfile.read())

        public_key = jwk.JWK()
        public_key.import_key(**json_decode(encrypt_key.export_public()))
        protected_header = {
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "typ": "JWE",
            "kid": public_key.thumbprint(),
        }

        message = json.dumps(packet)

        jwetoken = jwe.JWE(
            message.encode("utf-8"), recipient=public_key, protected=protected_header
        )

        self.logger.debug(f"Encrypted message: {packet['id']}")
        return jwetoken.serialize()


plugins["encrypt_filter"] = EncryptFilter()


class DecryptFilter(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.filter.decrypt")

    def do_action(self, packet):
        if "key" not in self.config:
            return packet

        if type(packet) is not str:
            self.logger.warning(f"Packet is not string")
            return packet

        from jwcrypto import jwk, jwe

        with open(self.config["key"], "rb") as pemfile:
            private_key = jwk.JWK.from_pem(pemfile.read())

        jwetoken = jwe.JWE()
        jwetoken.deserialize(packet, key=private_key)
        payload = jwetoken.payload
        packet = json.loads(payload)
        self.logger.debug(f"Decrypted message: {packet['id']}")
        return packet


plugins["decrypt_filter"] = DecryptFilter()


class RadioMessagePlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.send")

    def do_action(self, packet):
        if self.config["device"] not in self.devices:
            self.logger.error(f"Missing interface for device {self.config['device']}")
            return packet

        destinationId = None

        if "to" in self.config:
            destinationId = self.config["to"]
        elif "toId" in self.config:
            destinationId = self.config["toId"]
        elif "node_mapping" in self.config and "to" in packet:
            destinationId = self.config["node_mapping"][packet["to"]]
        elif "to" in packet:
            destinationId = packet["to"]
        elif "toId" in packet:
            destinationId = packet["toId"]

        if not destinationId:
            self.logger.error("Missing 'to' property in config or packet")
            return packet

        device_name = self.config["device"]

        device = self.devices[device_name]

        # Not a radio packet
        if "decoded" in packet and "text" in packet["decoded"] and "from" not in packet:
            self.logger.debug(f"Sending text to Radio {device_name}")
            device.sendText(text=packet["decoded"]["text"], destinationId=destinationId)

        elif (
            "lat" in self.config
            and self.config["lat"] > 0
            and "lng" in self.config
            and self.config["lng"] > 0
        ):
            lat = self.config["lat"]
            lng = self.config["lng"]
            altitude = self.config["alt"] if "alt" in self.config else 0

            self.logger.debug(f"Sending position to Radio {device_name}")

            device.sendPosition(
                latitude=lat,
                longitude=lng,
                altitude=altitude,
                destinationId=destinationId,
            )
        elif (
            "decoded" in packet
            and "payload" in packet["decoded"]
            and "portnum" in packet["decoded"]
        ):
            meshPacket = mesh_pb2.MeshPacket()
            meshPacket.channel = 0
            meshPacket.decoded.payload = base64.b64decode(packet["decoded"]["payload"])
            meshPacket.decoded.portnum = packet["decoded"]["portnum"]
            meshPacket.decoded.want_response = False
            meshPacket.id = device._generatePacketId()

            self.logger.debug(f"Sending packet to Radio {device_name}")

            device._sendPacket(meshPacket=meshPacket, destinationId=destinationId)

        return packet


plugins["radio_message_plugin"] = RadioMessagePlugin()


import time
from nostr.event import Event
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType
from nostr.key import PrivateKey, PublicKey


class NoStrPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.nostr_send")

    def do_action(self, packet):
        relays = ["wss://nostr-pub.wellorder.net", "wss://relay.damus.io"]

        for config_value in ["private_key", "public_key"]:
            if config_value not in self.config:
                self.logger.debug(f"Missing {config_value}")
                return packet

        # configure relays
        if "relays" in self.config:
            for relay in self.config["relays"]:
                relays.append(relay)

        relay_manager = RelayManager()

        for relay in relays:
            relay_manager.add_relay(relay)

        self.logger.debug(f"Opening connection to NoStr relays...")

        relay_manager.open_connections(
            {"cert_reqs": ssl.CERT_NONE}
        )  # NOTE: This disables ssl certificate verification
        time.sleep(
            self.config["startup_wait"] if "startup_wait" in self.config else 1.25
        )  # allow the connections to open

        # Opportunistically use environment variable
        for ek, ev in os.environ.items():
            needle = "{" + ek + "}"
            if needle in self.config["private_key"]:
                self.config["private_key"] = self.config["private_key"].replace(
                    needle, ev
                )

        private_key = PrivateKey.from_nsec(self.config["private_key"])
        public_key = PublicKey.from_npub(self.config["public_key"])

        if "message" in self.config:
            message = self.config["message"].replace("{MSG}", packet["decoded"]["text"])
        else:
            message = packet["decoded"]["text"]

        event = Event(content=message, public_key=public_key.hex())
        private_key.sign_event(event)

        self.logger.debug(f"Sending message to NoStr ...")
        relay_manager.publish_event(event)
        self.logger.info(f"Sent message to NoStr")

        time.sleep(
            self.config["publish_wait"] if "publish_wait" in self.config else 1
        )  # allow the messages to send

        relay_manager.close_connections()

        return packet


plugins["nostr_plugin"] = NoStrPlugin()


class TimestampPlugin(Plugin):
    logger = logging.getLogger(name="meshtastic.bridge.plugin.timestamp")

    def do_action(self, packet):
        import time
        from datetime import datetime

        # Default field name
        field_name = self.config.get("field", "timestamp") if self.config else "timestamp"

        # Default format is unix epoch
        format_type = self.config.get("format", "unix") if self.config else "unix"

        if format_type == "unix":
            timestamp = int(time.time())
        elif format_type == "unix_ms":
            timestamp = int(time.time() * 1000)
        elif format_type == "iso":
            timestamp = datetime.utcnow().isoformat() + "Z"
        elif format_type == "iso_local":
            timestamp = datetime.now().isoformat()
        else:
            self.logger.warning(f"Unknown format type: {format_type}, using unix")
            timestamp = int(time.time())

        # Add timestamp to packet at top level
        if isinstance(packet, dict):
            packet[field_name] = timestamp
            self.logger.debug(f"Added timestamp: {field_name}={timestamp}")
        else:
            self.logger.warning("Packet is not a dict, cannot add timestamp")

        return packet


plugins["timestamp_plugin"] = TimestampPlugin()


class StoreForwardPlugin(Plugin):
    """
    Store & Forward Plugin - Aggressive Mode

    Stores ALL directed messages and automatically delivers them when destination
    nodes are in range. This ensures messages are never lost due to nodes being
    out of range, even if they appear recently active.

    Features:
    - Stores all directed messages (not just for offline nodes)
    - Attempts immediate delivery if node was recently seen
    - Two-tier cleanup: delivered messages (2hr grace) + undelivered (48hr TTL)
    - Persistent SQLite storage survives bridge restarts
    """

    logger = logging.getLogger(name="meshtastic.bridge.plugin.store_forward")

    def __init__(self):
        super().__init__()
        self.db = None
        self.device_ref = None
        self.packet_count = 0  # For periodic cleanup
        self.configured = False  # Track if already configured

    def configure(self, devices, mqtt_servers, config):
        """Initialize plugin with configuration (only once)"""
        # Skip if already configured
        if self.configured:
            return

        super().configure(devices, mqtt_servers, config)

        # Validate required configuration
        if not config or 'storage_path' not in config:
            raise ValueError("store_forward_plugin requires 'storage_path' configuration")

        if 'device' not in config:
            raise ValueError("store_forward_plugin requires 'device' configuration")

        # Load configuration with defaults
        self.storage_path = config['storage_path']
        self.device_name = config['device']
        self.ttl_hours = config.get('ttl_hours', 48)
        self.delivered_retention_hours = config.get('delivered_retention_hours', 2)
        self.max_messages_per_node = config.get('max_messages_per_node', 500)
        self.offline_threshold_minutes = config.get('offline_threshold_minutes', 30)

        # Store devices reference for lazy loading
        self.devices = devices
        self.device_ref = None
        self.bridge_node_id = None  # Will be populated when device is available

        # Initialize database
        self._init_database()

        self.logger.info(f"Store & Forward plugin initialized (Aggressive Mode)")
        self.logger.info(f"Storage: {self.storage_path}")
        self.logger.info(f"TTL: {self.ttl_hours}h, Grace period: {self.delivered_retention_hours}h")
        self.logger.info(f"Max messages per node: {self.max_messages_per_node}")

        self.configured = True

    def _init_database(self):
        """Initialize SQLite database with schema"""
        try:
            self.db = sqlite3.connect(self.storage_path, check_same_thread=False)
            cursor = self.db.cursor()

            # Create messages table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_node TEXT NOT NULL,
                    from_node TEXT NOT NULL,
                    packet_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    delivered INTEGER DEFAULT 0,
                    delivered_at INTEGER
                )
            """)

            # Create indexes for efficient queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_to_node
                ON messages(to_node)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_delivered
                ON messages(delivered)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_delivered_at
                ON messages(delivered_at)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_expires
                ON messages(expires_at)
            """)

            # Create node_presence table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS node_presence (
                    node_id TEXT PRIMARY KEY,
                    last_seen INTEGER NOT NULL,
                    status TEXT DEFAULT 'unknown'
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_node_presence_last_seen
                ON node_presence(last_seen)
            """)

            self.db.commit()

            # Log database stats
            cursor.execute("SELECT COUNT(*) FROM messages WHERE delivered=0")
            undelivered = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM node_presence")
            nodes = cursor.fetchone()[0]

            self.logger.info(f"Database initialized: {undelivered} undelivered messages, {nodes} tracked nodes")

        except sqlite3.Error as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise

    def _extract_node_id(self, packet, field):
        """
        Extract node ID from packet field ('from' or 'to')
        Handles both integer and hex string formats (e.g., '!bd5ba0ec')
        """
        if not packet or not isinstance(packet, dict):
            return None

        # Try both field and field + 'Id' variants
        node_id = packet.get(field) or packet.get(field + 'Id')

        if node_id is None:
            return None

        # Convert to string for consistent storage
        return str(node_id)

    def _update_node_presence(self, node_id):
        """Update last-seen timestamp for a node"""
        if not node_id:
            return

        try:
            now = int(time.time())
            cursor = self.db.cursor()

            # Insert or update node presence
            cursor.execute("""
                INSERT INTO node_presence (node_id, last_seen, status)
                VALUES (?, ?, 'online')
                ON CONFLICT(node_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    status = 'online'
            """, (node_id, now))

            self.db.commit()
            self.logger.debug(f"Updated presence for node {node_id}")

        except sqlite3.Error as e:
            self.logger.error(f"Failed to update node presence: {e}")

    def _is_node_recently_seen(self, node_id):
        """
        Check if node was seen recently (within offline_threshold_minutes)
        Used for immediate delivery attempts
        """
        if not node_id:
            return False

        try:
            cursor = self.db.cursor()
            threshold = int(time.time()) - (self.offline_threshold_minutes * 60)

            cursor.execute("""
                SELECT last_seen FROM node_presence
                WHERE node_id = ? AND last_seen >= ?
            """, (node_id, threshold))

            result = cursor.fetchone()
            return result is not None

        except sqlite3.Error as e:
            self.logger.error(f"Failed to check node presence: {e}")
            return False

    def _check_node_filter(self, node_id, filter_config):
        """
        Check if node passes allow/disallow filter
        Returns True if node should be processed, False otherwise
        """
        if not filter_config:
            return True  # No filter configured, allow all

        # Check disallow list first (takes precedence)
        if 'disallow' in filter_config:
            if node_id in filter_config['disallow']:
                self.logger.debug(f"Node {node_id} is in disallow list")
                return False

        # Check allow list
        if 'allow' in filter_config:
            if node_id in filter_config['allow']:
                return True
            else:
                self.logger.debug(f"Node {node_id} not in allow list")
                return False

        # No allow list configured, allow by default
        return True

    def _is_broadcast(self, to_node):
        """Check if destination is a broadcast address"""
        return to_node in ['^all', '4294967295', 'ffffffff']

    def _is_deliverable_packet(self, packet):
        """Check if packet type can be delivered (TEXT or POSITION only)"""
        if not packet or 'decoded' not in packet:
            return False

        decoded = packet['decoded']
        portnum = decoded.get('portnum', '')

        # Only TEXT_MESSAGE_APP and POSITION_APP can be delivered
        # return portnum in ['TEXT_MESSAGE_APP', 'POSITION_APP']
        return portnum in ['TEXT_MESSAGE_APP']

    def _should_store_packet(self, packet):
        """
        Check if packet should be stored (with optional filtering)
        Store directed messages and optionally broadcasts
        """
        if not packet or not isinstance(packet, dict):
            return False

        # Only store deliverable packet types (TEXT and POSITION)
        if not self._is_deliverable_packet(packet):
            if 'decoded' in packet and 'portnum' in packet['decoded']:
                self.logger.debug(f"Skipping non-deliverable packet type: {packet['decoded']['portnum']}")
            return False

        # Get destination node
        to_node = self._extract_node_id(packet, 'to')

        # Skip if no destination
        if not to_node:
            self.logger.debug("Skipping packet without destination")
            return False

        # Handle broadcasts
        is_broadcast = self._is_broadcast(to_node)
        if is_broadcast:
            # Check if broadcast storage is enabled
            if not self.config.get('store_broadcasts', False):
                self.logger.debug(f"Skipping broadcast message (to: {to_node}), broadcast storage disabled")
                return False
            # Broadcasts will be stored for all nodes in the allow list
            self.logger.debug(f"Broadcast message detected, will store for allowed nodes")
            return True

        # For directed messages: check destination node filter
        if 'to' in self.config:
            if not self._check_node_filter(to_node, self.config['to']):
                self.logger.debug(f"Destination node {to_node} filtered out")
                return False

        # Check sender node filter
        from_node = self._extract_node_id(packet, 'from')
        if from_node and 'from' in self.config:
            if not self._check_node_filter(from_node, self.config['from']):
                self.logger.debug(f"Sender node {from_node} filtered out")
                return False

        # Passed all filters
        return True

    def _store_packet(self, packet):
        """Store packet in database for later delivery"""
        try:
            to_node = self._extract_node_id(packet, 'to')
            from_node = self._extract_node_id(packet, 'from')

            if not to_node:
                return

            # Check if this is a broadcast
            is_broadcast = self._is_broadcast(to_node)

            # Serialize packet to JSON
            packet_json = json.dumps(packet)

            # Calculate timestamps
            now = int(time.time())
            expires_at = now + (self.ttl_hours * 3600)

            cursor = self.db.cursor()

            if is_broadcast and 'to' in self.config and 'allow' in self.config['to']:
                # Store broadcast for each node in the allow list
                allow_list = self.config['to']['allow']
                stored_count = 0

                for target_node in allow_list:
                    cursor.execute("""
                        INSERT INTO messages (to_node, from_node, packet_json, created_at, expires_at, delivered)
                        VALUES (?, ?, ?, ?, ?, 0)
                    """, (target_node, from_node or 'unknown', packet_json, now, expires_at))
                    stored_count += 1

                    # Enforce per-node message limit
                    self._enforce_node_limit(target_node)

                self.db.commit()
                self.logger.info(f"Stored broadcast from {from_node} for {stored_count} nodes")

            else:
                # Store directed message normally
                cursor.execute("""
                    INSERT INTO messages (to_node, from_node, packet_json, created_at, expires_at, delivered)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (to_node, from_node or 'unknown', packet_json, now, expires_at))

                message_id = cursor.lastrowid
                self.db.commit()

                self.logger.info(f"Stored message {message_id}: {from_node} → {to_node}")

                # Enforce per-node message limit
                self._enforce_node_limit(to_node)

        except sqlite3.Error as e:
            self.logger.error(f"Failed to store packet: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to serialize packet: {e}")

    def _enforce_node_limit(self, node_id):
        """Enforce max_messages_per_node limit by removing oldest undelivered messages"""
        try:
            cursor = self.db.cursor()

            # Count undelivered messages for this node
            cursor.execute("""
                SELECT COUNT(*) FROM messages
                WHERE to_node = ? AND delivered = 0
            """, (node_id,))

            count = cursor.fetchone()[0]

            if count > self.max_messages_per_node:
                # Delete oldest messages beyond limit
                delete_count = count - self.max_messages_per_node
                cursor.execute("""
                    DELETE FROM messages
                    WHERE id IN (
                        SELECT id FROM messages
                        WHERE to_node = ? AND delivered = 0
                        ORDER BY created_at ASC
                        LIMIT ?
                    )
                """, (node_id, delete_count))

                self.db.commit()
                self.logger.warning(f"Enforced message limit for node {node_id}: removed {delete_count} oldest messages")

        except sqlite3.Error as e:
            self.logger.error(f"Failed to enforce node limit: {e}")

    def _deliver_stored_messages(self, node_id):
        """Deliver all stored messages for a node (called when node comes online)"""
        if not node_id:
            return

        # Check if device is available
        if not self._get_device_ref():
            self.logger.debug(f"Cannot deliver messages, device not yet available")
            return

        try:
            cursor = self.db.cursor()

            # Get all undelivered messages for this node (FIFO order)
            # Exclude messages the node itself sent (from_node != to_node)
            cursor.execute("""
                SELECT id, packet_json, from_node, created_at
                FROM messages
                WHERE to_node = ? AND delivered = 0 AND from_node != ?
                ORDER BY created_at ASC
            """, (node_id, node_id))

            messages = cursor.fetchall()

            if not messages:
                return

            self.logger.info(f"Delivering {len(messages)} stored messages to node {node_id}")

            delivered_count = 0
            for msg_id, packet_json, from_node, created_at in messages:
                try:
                    # Deserialize packet
                    packet = json.loads(packet_json)

                    # Send message with metadata
                    if self._send_packet_to_node(packet, node_id, from_node, created_at):
                        # Mark as delivered
                        self._mark_delivered(msg_id)
                        delivered_count += 1
                        self.logger.info(f"Delivered message {msg_id} to {node_id} from {from_node}")
                    else:
                        self.logger.warning(f"Failed to deliver message {msg_id} to {node_id}")

                    # Rate limiting (1 message per second)
                    time.sleep(1)

                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to deserialize message {msg_id}: {e}")
                except Exception as e:
                    self.logger.error(f"Failed to deliver message {msg_id}: {e}")

            self.logger.info(f"Delivered {delivered_count}/{len(messages)} messages to {node_id}")

        except sqlite3.Error as e:
            self.logger.error(f"Failed to retrieve stored messages: {e}")

    def _get_device_ref(self):
        """Lazy-load device reference (may not be available at configure time)"""
        if not self.device_ref and self.device_name in self.devices:
            self.device_ref = self.devices[self.device_name]
            self.logger.info(f"Device '{self.device_name}' connected and ready for store & forward")

            # Get bridge node ID
            try:
                node_info = self.device_ref.getMyNodeInfo()
                self.bridge_node_id = str(node_info['num'])
                self.logger.info(f"Bridge node ID: {self.bridge_node_id}")
            except Exception as e:
                self.logger.warning(f"Could not get bridge node ID: {e}")

        return self.device_ref

    def _node_id_to_hex(self, node_id):
        """Convert node ID (string or int) to hex format (!xxxxxxxx)"""
        try:
            node_int = int(node_id)
            return f"!{node_int:08x}"
        except (ValueError, TypeError):
            return str(node_id)

    def _format_timestamp(self, timestamp):
        """Format unix timestamp to readable string"""
        from datetime import datetime
        try:
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return str(timestamp)

    def _send_packet_to_node(self, packet, node_id, from_node=None, created_at=None):
        """
        Send packet to node via device interface
        Returns True if send successful, False otherwise

        Args:
            packet: The packet to send
            node_id: Destination node ID
            from_node: Original sender (for metadata)
            created_at: Original timestamp (for metadata)
        """
        device = self._get_device_ref()
        if not device:
            self.logger.debug(f"Device '{self.device_name}' not yet available for sending")
            return False

        try:
            # Convert node_id to integer for Meshtastic API
            # node_id is stored as string (e.g., "1119572084"), API needs int
            try:
                destination_id = int(node_id)
            except (ValueError, TypeError):
                self.logger.error(f"Invalid node_id format: {node_id}")
                return False

            # Extract message content
            if 'decoded' not in packet:
                self.logger.warning(f"Packet has no decoded content, skipping")
                return False

            decoded = packet['decoded']

            # Handle text messages
            if 'text' in decoded:
                original_text = decoded['text']

                # Add metadata if this is a stored message
                if from_node and created_at:
                    from_hex = self._node_id_to_hex(from_node)
                    to_hex = self._node_id_to_hex(node_id)
                    timestamp_str = self._format_timestamp(created_at)

                    # Extract channel (try multiple possible locations)
                    channel = packet.get('channel')
                    if channel is None:
                        channel = decoded.get('channel')
                    if channel is None:
                        # Check if it's a channelId field
                        channel = packet.get('channelId', decoded.get('channelId'))

                    # Debug: log packet keys to help identify channel field
                    self.logger.debug(f"Packet keys: {list(packet.keys())}")

                    # Format channel display
                    if channel is not None:
                        channel_str = f"Channel: {channel}"
                    else:
                        channel_str = "Channel: Primary"  # Default assumption

                    # Format message with metadata
                    text = f"[Stored Message]\nFrom: {from_hex}\nTo: {to_hex}\nSent: {timestamp_str}\n{channel_str}\n---\n{original_text}"
                else:
                    text = original_text

                device.sendText(text=text, destinationId=destination_id)
                self.logger.info(f"Sent text message to {node_id}: '{original_text}'")
                return True

            # Handle position messages
            elif 'position' in decoded:
                pos = decoded['position']
                if 'latitude' in pos and 'longitude' in pos:
                    # For positions, send metadata as separate text message first
                    if from_node and created_at:
                        from_hex = self._node_id_to_hex(from_node)
                        timestamp_str = self._format_timestamp(created_at)
                        metadata_text = f"[Stored Position]\nFrom: {from_hex}\nSent: {timestamp_str}"
                        device.sendText(text=metadata_text, destinationId=destination_id)
                        time.sleep(1)  # Brief delay between messages

                    device.sendPosition(
                        latitude=pos.get('latitude'),
                        longitude=pos.get('longitude'),
                        altitude=pos.get('altitude', 0),
                        destinationId=destination_id
                    )
                    self.logger.info(f"Sent position to {node_id}")
                    return True

            else:
                self.logger.warning(f"Unknown packet type, cannot send to {node_id}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to send packet to {node_id}: {e}")
            return False

    def _mark_delivered(self, message_id):
        """Mark message as delivered with timestamp (but keep for grace period)"""
        try:
            now = int(time.time())
            cursor = self.db.cursor()

            cursor.execute("""
                UPDATE messages
                SET delivered = 1, delivered_at = ?
                WHERE id = ?
            """, (now, message_id))

            self.db.commit()
            self.logger.debug(f"Marked message {message_id} as delivered")

        except sqlite3.Error as e:
            self.logger.error(f"Failed to mark message as delivered: {e}")

    def _cleanup_old_messages(self):
        """
        Two-tier cleanup strategy:
        1. Delete delivered messages past grace period (2 hours default)
        2. Delete undelivered messages past TTL (48 hours default)
        """
        try:
            cursor = self.db.cursor()
            now = int(time.time())

            # Tier 1: Clean up delivered messages past grace period
            grace_period_threshold = now - (self.delivered_retention_hours * 3600)

            cursor.execute("""
                DELETE FROM messages
                WHERE delivered = 1 AND delivered_at < ?
            """, (grace_period_threshold,))

            delivered_cleaned = cursor.rowcount

            # Tier 2: Clean up undelivered messages past TTL
            cursor.execute("""
                DELETE FROM messages
                WHERE delivered = 0 AND expires_at < ?
            """, (now,))

            undelivered_cleaned = cursor.rowcount

            self.db.commit()

            if delivered_cleaned > 0 or undelivered_cleaned > 0:
                self.logger.info(
                    f"Cleanup: removed {delivered_cleaned} delivered messages (past grace period), "
                    f"{undelivered_cleaned} undelivered messages (past TTL)"
                )

        except sqlite3.Error as e:
            self.logger.error(f"Failed to cleanup old messages: {e}")

    def _should_track_node(self, node_id):
        """Check if we should track this node (based on allow list)"""
        if not node_id:
            return False

        # If there's an allow list, only track nodes in it
        if 'to' in self.config and 'allow' in self.config['to']:
            return node_id in self.config['to']['allow']

        # No allow list = track all nodes
        return True

    def _should_trigger_delivery(self, packet):
        """
        Check if packet should trigger delivery of stored messages
        Triggers on NODEINFO_APP packets from tracked nodes (natural "I'm online" signal)
        """
        if not packet or not isinstance(packet, dict):
            return False

        # Check if it's a NODEINFO_APP packet
        if 'decoded' in packet:
            portnum = packet['decoded'].get('portnum', '')
            if portnum == 'TEXT_MESSAGE_APP':
                text = packet['decoded'].get('text', '').strip().lower()
                if text == '!get':
                    return True
            # if portnum == 'NODEINFO_APP':
            #     return True

        return False

    def do_action(self, packet):
        """Main packet processing entry point - AGGRESSIVE MODE"""
        if not packet or not isinstance(packet, dict):
            return packet

        try:
            # 1. Update node presence from sender (only if we're tracking this node)
            from_node = self._extract_node_id(packet, 'from')
            if from_node and self._should_track_node(from_node):
                self.logger.debug(f"Node {from_node} seen, updating presence")
                self._update_node_presence(from_node)

                # Check if this is a NODEINFO packet (node announcing itself / coming online)
                if self._should_trigger_delivery(packet):
                    self.logger.info(f"Node {from_node} announced itself (NODEINFO), triggering delivery")
                    self._deliver_stored_messages(from_node)

            # 2. Store ALL directed messages (AGGRESSIVE MODE)
            if self._should_store_packet(packet):
                to_node = self._extract_node_id(packet, 'to')
                self.logger.info(f"Storing message: {from_node} → {to_node}")
                self._store_packet(packet)

                # 3. Attempt immediate delivery if destination node was recently seen
                if to_node and self._is_node_recently_seen(to_node):
                    self.logger.info(f"Destination {to_node} was recently seen, attempting immediate delivery")
                    # Try immediate delivery (optimistic)
                    if self._send_packet_to_node(packet, to_node, from_node, int(time.time())):
                        self.logger.info(f"Immediate delivery succeeded for {to_node}")
                    else:
                        self.logger.warning(f"Immediate delivery failed for {to_node}, will retry later")

            # 4. Periodic cleanup (every 100 packets)
            self.packet_count += 1
            if self.packet_count >= 100:
                self._cleanup_old_messages()
                self.packet_count = 0

        except Exception as e:
            self.logger.error(f"Error in do_action: {e}", exc_info=True)

        return packet


plugins["store_forward_plugin"] = StoreForwardPlugin()
