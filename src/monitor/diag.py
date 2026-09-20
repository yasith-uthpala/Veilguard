import psutil, socket

print("=== All interfaces with IPv4 ===")
for name, addrs in psutil.net_if_addrs().items():
    for addr in addrs:
        if addr.family == socket.AF_INET:
            print(f"  {name}: {addr.address}")

print()
print("=== IO Counters (bytes_sent) ===")
for name, counters in psutil.net_io_counters(pernic=True).items():
    print(f"  {name}: sent={counters.bytes_sent}")

print()
print("=== Scapy Windows interface list ===")
from scapy.arch.windows import get_windows_if_list
for e in get_windows_if_list():
    print(f"  name={e.get('name')}  guid={e.get('guid')}")