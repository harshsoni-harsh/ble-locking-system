from typing import Optional

from bluez_peripheral.util import Adapter
from dbus_next.constants import MessageType
from dbus_next.message import Message

def normalize_mac(value: Optional[str]) -> Optional[str]:
	if not value:
		return None
	return value.replace("-", ":").upper()

async def get_first_adapter(bus) -> Adapter:
	message = Message(
		destination="org.bluez",
		path="/",
		interface="org.freedesktop.DBus.ObjectManager",
		member="GetManagedObjects",
	)
	reply = await bus.call(message)
	if reply.message_type == MessageType.ERROR:
		raise RuntimeError(
			f"GetManagedObjects failed: {reply.error_name} {reply.body}"
		)

	objects = reply.body[0]
	for path, interfaces in objects.items():
		if "org.bluez.Adapter1" in interfaces:
			introspection = await bus.introspect("org.bluez", path)
			proxy = bus.get_proxy_object("org.bluez", path, introspection)
			return Adapter(proxy)

	raise ValueError("No bluetooth adapters could be found.")
