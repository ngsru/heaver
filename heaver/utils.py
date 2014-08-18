import fcntl

def sync_open(filename, mode):
    f = open(filename, mode)
    fcntl.flock(f, fcntl.LOCK_EX)
    return f