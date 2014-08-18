import subprocess
import time
import multiprocessing


def get_ram():
    "Return memory usage stats from /proc/meminfo"
    lines = open("/proc/meminfo").read().strip().split("\n") # FIXME: file missing => system broken
    stats = dict()
    for line in lines:
        name, _colon, value = line.partition(":")
        if value.endswith(" kB"):
            value = value[:-3]
        stats[name] = int(value)

    total = stats["MemTotal"]
    soft_used = total - stats["MemFree"]
    hard_used = soft_used - stats["Buffers"] - stats["Cached"]

    swap_total = stats["SwapTotal"]
    swap_used = swap_total - stats["SwapFree"]

    return dict(total=total, soft_used=soft_used, hard_used=hard_used, swap_total=swap_total,
        swap_used=swap_used)


def get_la():
    "Return load average and process stat"
    line = open("/proc/loadavg").read().strip() # FIXME: file missing => system broken
    avg1, avg5, avg15, procs, _lastpid = line.split(" ")
    running, _slash, total = procs.partition("/")
    cpus = multiprocessing.cpu_count()
    return dict(avg1=float(avg1), avg5=float(avg5), avg15=float(avg15), running=int(running),
        total=int(total), cpus=cpus)


def get_oom_stats(hours=1):
    dmesg = subprocess.Popen(["dmesg"], stdout=subprocess.PIPE).communicate()[0]
    now = time.time()
    uptime = open("/proc/uptime").read().split(" ")[0]
    uptime = float(uptime)
    prev_check = max(0, uptime - 3600 * hours)

    ooms = []
    for line in dmesg.split("\n"):
        when, message = find_oom(line, prev_check)
        if when and message:
            abs_time = now - uptime + when
            ooms.append((abs_time, message))

    return ooms


def find_oom(line, since):
    if not line.startswith("["): # multiline message
        return None, None
    when, _braket, message = line[1:].partition("] ")
    when = float(when)
    if when > since:
        if message.startswith("Out of memory:"):
            return when, message

    return None, None

