import datetime
import copy
import logging
import random

"""
Pool structure:
    HOSTS: {HOSTNAME: HOST}
    HOSTNAME: string
    HOST: {HOSTNAME, vms: [VM], ips: [RANGE], last_seen: date,
        score: int, available: bool, status: (tag, desc)}
    VM: {hostname: string, other vm data..., ips: [VMNET]}
    RANGE: [(ipaddr, mask)]
    VMNET: {hwaddr: string, ips: [ipaddr], vlan?}

Pool role:
    Balancing over hosts
    Statistics"""


logger = logging.getLogger("heaver.daemon.pool")

# default coefficients for calculate_score
# see _scale function
COEFFS = dict(
    la=(1, -1, 4),
    la_tag="avg5",
    ram=(1, 1.0/1024/1024, 0), # scale to gb of ram
    ram_tag="hard_used",
    fs=(1, 1.0/1024/1024/10, 0), # scale to tens gb of disk
    boxes=(1.1, -1, 0),
    seen_timeout=datetime.timedelta(minutes=8),
    timed_out_scale=0.3,
)
BASE_SCORE = 100

class NoHostAvailable(Exception): pass

class Pool(object):
    "Pool of hosts"

    def __init__(self, heartbeat_timeout, hosts=None):
        self.heartbeat_timeout = heartbeat_timeout
        if hosts:
            self.hosts = hosts
        else:
            self.hosts = dict()

    def update_host(self, hostname, host):
        "Update host status"
        last_time = self.hosts.get(hostname, dict()).get("now", 0)
        if host.get("now", 0) < last_time: # already have newer update
            return
        host = copy.deepcopy(host) # FIXME: check host data
        host["last_seen"] = datetime.datetime.now()
        host["alive"] = True
        self.hosts[hostname] = host # FIXME: update with logging

    def choose_host(self):
        "Choose most fitting host"
        scores = []
        for hostname, host in self.hosts.items():
            score = calculate_score(host, COEFFS, BASE_SCORE)
            if score > 0:
                scores.append((hostname, score))

        if len(scores) == 0:
            # no available hosts found
            raise NoHostAvailable("No hosts available in pool. %d hosts total" % len(self.hosts))

        return choose_weighted(scores)

    def get_stale(self):
        stale = []
        now = datetime.datetime.now()
        for host in self.hosts.values():
            if (now - host["last_seen"]).total_seconds() > self.heartbeat_timeout:
                stale.append(host)
        return stale

    def get_stats(self):
        "Calculate statistics of pool"
        hosts = copy.deepcopy(self.hosts)
        now = datetime.datetime.now()
        for host in hosts.values():
            host["score"] = calculate_score(host, COEFFS, BASE_SCORE)
            stale = (now - host["last_seen"]).total_seconds() > self.heartbeat_timeout
            host["stale"] = stale
        return hosts

    def get_hosts(self):
        return self.hosts # TODO: drop internal fields

    def get_host(self, hostname):
        if hostname in self.hosts:
            return self.hosts[hostname]
        else:
            raise NoHostAvailable("No such host")


def calculate_score(host, coeffs, base_score, ips_needed=1):
    "Calculate resource score for host, the higher is better"
    scores = []
    score = base_score
    scores.append(("base_score", 1, base_score, base_score))
    if not host["alive"]:
        return 0

    if host["ips_free"] < ips_needed:
        return 0

    # la
    la_score = _scale(coeffs["la"], host["la"]["cpus"] - host["la"][coeffs["la_tag"]])
    score += la_score
    logger.info("counting scores")
    scores.append(("la_score", coeffs["la"], host["la"]["cpus"] - host["la"][coeffs["la_tag"]],
                   la_score))

    # ram
    ram_score = _scale(coeffs["ram"], host["ram"]["total"] - host["ram"][coeffs["ram_tag"]])
    score += ram_score
    scores.append(("ram_score", coeffs["ram"],
                   host["ram"]["total"] - host["ram"][coeffs["ram_tag"]], ram_score))

    # fs
    fs_score = _scale(coeffs["fs"], host["fs"])
    score += fs_score
    scores.append(("fs_score", coeffs["fs"], host["fs"], fs_score))
    logger.debug("fs score got")

    # boxes
    active_boxes = filter(lambda box: box["active"], host["boxes"].values())
    boxes_score = _scale(coeffs["boxes"], len(active_boxes))
    score += boxes_score
    scores.append(("boxes_score", coeffs["boxes"], len(active_boxes), boxes_score))

    # NOTE: oom & timeout are health parameters
    # oom
    oom_score = len(host["oom"]) + 1
    score /= oom_score
    scores.append(("oom_score", 1, len(host["oom"]), oom_score))

    # timeouts
    if host["last_seen"] < datetime.datetime.now() - coeffs["seen_timeout"]:
        timeout_score = coeffs["timed_out_scale"]
        score *= timeout_score
        scores.append(("timed_out_score", 1, timeout_score, timeout_score))

    scores.append(("final_score", 1, 0, score))
    # format and log scores
    formatted_scores = "\n".join(map(lambda tpl: "%s: coeff %r value %r score %f" % tpl, scores))
    logger.debug(formatted_scores)
    print formatted_scores
    return score

def _scale(coeff, value):
    power, mult, base = coeff
    return pow(value, power) * mult + base

def choose_weighted(scores):
    if len(scores) == 0:
        return None
    score_sum = sum(map(lambda s: s[1], scores))
    # throw random point
    point = random.random() * score_sum

    boundary = 0
    for hostname, score in scores:
        boundary += score
        # find hit segment
        if point <= boundary:
            return hostname

    return None

