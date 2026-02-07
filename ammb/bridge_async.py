# ammb/bridge_async.py
"""
Async Bridge orchestrator using MeshcoreAsyncHandler.
"""

import asyncio
import logging
from typing import Optional

from ammb.meshcore_async_handler import MeshcoreAsyncHandler
from ammb.mqtt_async_handler import MQTTAsyncHandler
from ammb.config_handler import BridgeConfig



class AsyncBridge:
    def __init__(self, config: BridgeConfig):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.meshcore_handler: Optional[MeshcoreAsyncHandler] = None
        self.mqtt_handler: Optional[MQTTAsyncHandler] = None
        self._running = False

    async def start(self):
        self._running = True
        try:
            if self.config.external_transport == "serial":
                self.meshcore_handler = MeshcoreAsyncHandler(
                    serial_port=self.config.serial_port,
                    baud=self.config.serial_baud or 115200,
                    debug=self.config.log_level == "DEBUG",
                )
                try:
                    # Subscribe to incoming message events before connect
                    from meshcore import EventType
                    self.meshcore_handler.subscribe(
                        EventType.CONTACT_MSG_RECV, self.handle_incoming_message
                    )
                    self.meshcore_handler.subscribe(
                        EventType.CHANNEL_MSG_RECV, self.handle_incoming_message
                    )
                    await self.meshcore_handler.run()
                except Exception as e:
                    self.logger.error(f"Unhandled exception in meshcore handler: {e}", exc_info=True)
            elif self.config.external_transport == "mqtt":
                self.mqtt_handler = MQTTAsyncHandler(
                    broker=self.config.mqtt_broker,
                    port=self.config.mqtt_port,
                    topic_in=self.config.mqtt_topic_in,
                    topic_out=self.config.mqtt_topic_out,
                    username=self.config.mqtt_username,
                    password=self.config.mqtt_password,
                    qos=self.config.mqtt_qos or 0,
                    retain=self.config.mqtt_retain_out or False,
                    tls=self.config.mqtt_tls_enabled or False,
                    tls_ca_certs=self.config.mqtt_tls_ca_certs,
                    tls_insecure=self.config.mqtt_tls_insecure or False,
                    client_id=self.config.mqtt_client_id,
                )
                try:
                    self.mqtt_handler.set_message_handler(self.handle_mqtt_message)
                    await self.mqtt_handler.connect()
                    await self.mqtt_handler.run()
                except Exception as e:
                    self.logger.error(f"Unhandled exception in MQTT handler: {e}", exc_info=True)
            else:
                self.logger.error("Unsupported external transport in async bridge.")
        except asyncio.CancelledError:
            self.logger.info("AsyncBridge received cancellation signal.")
        except Exception as e:
            self.logger.critical(f"Unhandled exception in AsyncBridge: {e}", exc_info=True)
        finally:
            await self.shutdown()

    async def shutdown(self):
        self.logger.info("Shutting down AsyncBridge and handlers...")
        self._running = False
        if self.meshcore_handler:
            await self.meshcore_handler.disconnect()
        if self.mqtt_handler:
            await self.mqtt_handler.disconnect()
        self.logger.info("AsyncBridge shutdown complete.")

    async def handle_incoming_message(self, event):
        try:
            self.logger.info(f"Received message: {event.payload}")
            # Add additional async message processing here
        except Exception as e:
            self.logger.error(f"Error in handle_incoming_message: {e}", exc_info=True)

    def handle_mqtt_message(self, data):
        try:
            self.logger.info(f"Received MQTT message: {data}")
            # Add additional async message processing here if needed
        except Exception as e:
            self.logger.error(f"Error in handle_mqtt_message: {e}", exc_info=True)
