import threading
import Queue
import copy

import heaver.daemon.pool as pool


class Tracker(object):
    "Tracks state of the daemon, hosts, vms"

    def __init__(self):
        self._pool = pool.Pool(10)

        self._pool_lock = threading.Lock()

    def get_hosts(self):
        with self._pool_lock:
            return copy.deepcopy(self._pool.get_hosts())

    def get_host(self, hostname):
        with self._pool_lock:
            return copy.deepcopy(self._pool.get_host(hostname))

    def get_boxes(self):
        with self._pool_lock:
            boxes = []
            for hostname, host in self._pool.get_hosts().items():
                host_boxes = copy.deepcopy(host["boxes"])
                for name, box in host_boxes.items():
                    box["name"] = name
                    box["running_on"] = hostname
                    boxes.append(box)
            return boxes

    def get_box(self, hostname, boxname):
        with self._pool_lock:
            host = self._pool.get_host(hostname)
            boxes = host["boxes"]
            # FIXME: boxes must be container specs
            return boxname in boxes
        return None

    def get_balanced_host(self):
        with self._pool_lock:
            return self._pool.choose_host() # TODO: reserve resources?

    def find_host_for_box(self, boxname):
        with self._pool_lock:
            for hostname, host in self._pool.get_hosts().items():
                if boxname in host["boxes"]:
                    return hostname
            return None

    def update_host(self, hostname, update_info):
        # print "updating host", hostname
        with self._pool_lock:
            self._pool.update_host(hostname, update_info)

    def get_stats(self):
        "Return statistic for compute pool"
        with self._pool_lock:
            return self._pool.get_stats()
