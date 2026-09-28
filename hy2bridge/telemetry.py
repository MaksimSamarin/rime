"""Host resource samples, independent of request worker threads."""
import threading
import time
import socket


def complete_resources(node,now=None):
    now=time.time() if now is None else now
    m=node.get('metrics') or {};seen=node.get('seen_at')
    if not isinstance(seen,(int,float)) or not 0<=now-seen<=30:return False
    if type(m.get('cpu_percent')) not in (int,float) or not 0<=m['cpu_percent']<=100:return False
    for total,free in [('mem_total_bytes','mem_available_bytes'),('disk_total_bytes','disk_free_bytes')]:
        if type(m.get(total)) is not int or m[total]<=0 or type(m.get(free)) is not int or not 0<=m[free]<=m[total]:return False
    if any(type(m.get(k)) is not int or m[k]<0 for k in ['net_rx_bytes','net_tx_bytes','online_connections']):return False
    return m.get('service_healthy') is True


class HostResources:
    def __init__(self, psutil, disk_path):
        self.psutil = psutil
        self.disk_path = disk_path
        self.lock = threading.Lock()
        self.previous = None
        self.cpu = None

    def snapshot(self):
        with self.lock:
            now = time.monotonic()
            times = self.psutil.cpu_times()._asdict()
            # Linux guest time is already included in user/nice counters.
            total = sum(v for k, v in times.items() if k not in ('guest', 'guest_nice'))
            idle = times.get('idle', 0) + times.get('iowait', 0)
            if self.previous and now - self.previous[0] >= 1:
                delta = total - self.previous[1]
                self.cpu = max(0, min(100, round(100 * (1 - (idle - self.previous[2]) / delta), 1))) if delta > 0 else None
                self.previous = (now, total, idle)
            elif self.previous is None:
                self.previous = (now, total, idle)
            memory = self.psutil.virtual_memory()
            disk = self.psutil.disk_usage(self.disk_path)
            return {'cpu_percent': self.cpu, 'mem_total_bytes': memory.total,
                    'mem_available_bytes': memory.available, 'disk_total_bytes': disk.total,
                    'disk_free_bytes': disk.free}


class PanelRuntime:
    """Panel process identity and uptime; independent of the local VPN core."""
    def __init__(self, psutil, version):
        self.psutil = psutil
        self.process = psutil.Process()
        self.started_at = self.process.create_time()
        self.version = version
        self.hostname = socket.gethostname()

    def snapshot(self):
        now = time.time()
        return {'version': self.version, 'hostname': self.hostname,
                'uptime_seconds': max(0, int(now - self.started_at)),
                'host_uptime_seconds': max(0, int(now - self.psutil.boot_time())),
                'process_memory_bytes': self.process.memory_info().rss}
