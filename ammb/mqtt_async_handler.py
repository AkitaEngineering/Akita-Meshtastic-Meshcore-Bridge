# ammb/mqtt_async_handler.py
"""
Async MQTT handler using asyncio-mqtt for external network interface.
"""
import asyncio
import json
import logging
from typing import Any, Callable, Optional
from asyncio_mqtt import Client, MqttError

class MQTTAsyncHandler:
    def __init__(self, broker: str, port: int, topic_in: str, topic_out: str, username: Optional[str] = None, password: Optional[str] = None, qos: int = 0, retain: bool = False, tls: bool = False, tls_ca_certs: Optional[str] = None, tls_insecure: bool = False, client_id: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.broker = broker
        self.port = port
        self.topic_in = topic_in
        self.topic_out = topic_out
        self.username = username
        self.password = password
        self.qos = qos
        self.retain = retain
        self.tls = tls
        self.tls_ca_certs = tls_ca_certs
        self.tls_insecure = tls_insecure
        self.client_id = client_id
        self._client: Optional[Client] = None
        self._message_handler: Optional[Callable[[dict], None]] = None
        self._running = False

    async def connect(self):
        self._client = Client(self.broker, port=self.port, username=self.username, password=self.password, client_id=self.client_id)
        if self.tls:
            tls_params = {}
            if self.tls_ca_certs:
                tls_params['ca_certs'] = self.tls_ca_certs
            if self.tls_insecure:
                tls_params['cert_reqs'] = False
            self._client.tls_set(**tls_params)
        await self._client.connect()
        self.logger.info(f"Connected to MQTT broker {self.broker}:{self.port}")

    async def disconnect(self):
        if self._client:
            await self._client.disconnect()
            self.logger.info("Disconnected from MQTT broker.")

    async def publish(self, message: dict):
        if not self._client:
            raise RuntimeError("MQTT client not connected.")
        payload = json.dumps(message)
        await self._client.publish(self.topic_out, payload, qos=self.qos, retain=self.retain)
        self.logger.info(f"Published message to {self.topic_out}")

    def set_message_handler(self, handler: Callable[[dict], None]):
        self._message_handler = handler

    async def run(self):
        if not self._client:
            await self.connect()
        self._running = True
        async with self._client.unfiltered_messages() as messages:
            await self._client.subscribe(self.topic_in, qos=self.qos)
            self.logger.info(f"Subscribed to {self.topic_in}")
            async for msg in messages:
                try:
                    payload = msg.payload.decode('utf-8')
                    data = json.loads(payload)
                    if self._message_handler:
                        self._message_handler(data)
                except Exception as e:
                    self.logger.error(f"Error processing MQTT message: {e}")
                if not self._running:
                    break

    def stop(self):
        self._running = False
