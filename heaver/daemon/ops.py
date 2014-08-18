import threading
import logging
import json

import heaver.daemon.ssh as ssh

STREAM_CHUNK_SIZE = 4 * 1024 * 1024 # 4K
STREAM_BUFFER = 256 * 1024 * 1024 # 256M
STREAM_QUEUE_SIZE = 16
SSH_RECONNECT_RETRIES = 3

logger = logging.getLogger("heaver.daemon.operations")


class Pool(object):
    "Pool of connections to hosts"
    def __init__(self, username, key_path, tracker):
        self.username = username
        self.key_path = key_path
        self.tracker = tracker
        self.connections = dict()

        try:
            self.public_key = open(key_path + ".pub").read()
        except Exception as e:
            raise Exception("Can't load public key: ", str(e))

        self.conn_lock_master = threading.Lock()
        self.conn_locks = dict()

    def get(self, hostname):
        "Get operator for specified host"
        return Operator(hostname, self.tracker, self)

    def get_connection(self, hostname):
        "Get connection to host. To use by operators"
        host = self.tracker.get_host(hostname) # raises if host not in pool
        # get connection if have one
        with self.conn_lock_master:
            if hostname in self.connections:
                return self.connections[hostname]
            if self.conn_locks.get(hostname) is None:
                self.conn_locks[hostname] = threading.Lock()

        # establish connection under to host under its own lock
        with self.conn_locks[hostname]:
            conn = ssh.connect(hostname, self.username, self.key_path)
            with self.conn_lock_master:
                self.connections[hostname] = conn
                return conn


    def drop(self, hostname):
        "Close ssh connection to host"
        host = self.tracker.get_host(hostname)
        if hostname not in self.connections:
            return

        with self.conn_locks[hostname]:
            # .close may throw, thus remove conn from connections dict first
            conn = self.connections[hostname]
            del self.connections[hostname]
            conn.close()

    def get_public_key(self):
        return self.public_key


class OperationError(Exception):
    pass

class Operator(object):
    "Performs actions on remote compute node"

    def __init__(self, hostname, tracker, pool):
        self.hostname = hostname # read-only
        self.tracker = tracker # thread-safe
        self.pool = pool # thread-safe

    def start(self, name):
        "Starts existing instance"
        return self._execute_update(["--start", "-n", name])

    def stop(self, name):
        "Stops existing instance"
        return self._execute_update(["--stop", "-n", name])

    def create(self, name, image, opts=None):
        "Creates instance"
        args = []
        if opts is not None:
            if "net" in opts and opts["net"] is not None:
                for net in opts["net"]:
                    args += ["--net", net]
            if "key" in opts and opts["key"] is not None:
                args += ["--raw-key", opts["key"]]
            if "limit" in opts and isinstance(opts["limit"], list):
                for limit in opts["limit"]:
                    args += ["--limit", limit]
        for image_arg in image:
            args += ["--image", image_arg]
        return self._execute_update(["--create", "-n", name] + args)

    def destroy(self, name):
        "Destroys instance"
        return self._execute_update(["--destroy", "-n", name])

    def make_tarball(self, name):
        "Creates tarball of instance's root and return it as iterator"
        # create tarball first (in temporary file)
        out = self._execute(["--tarball", "-n", name])
        status = json.loads(out[-1])
        tar_path = status.get("data")
        if not tar_path: # WTF?
            logger.warning("failed to make tarball of container '%s' on host '%s'", name,
                           self.hostname)
            raise OperationError("cannot make tarball of container - status corrupted")

        # open sftp session and create file iterator
        sftp = self._try_invoke_sftp()
        try:
            tar_file = sftp.open(tar_path)
        except Exception as e:
            raise OperationError("Cannot open remote file: '%s'" % e)

        return stream_sftp_file(tar_file, tar_path, sftp)

    def ping(self):
        "Check that server responds by ssh"
        try:
            cmd, proc = self._invoke(["true"])
            exit_code = proc.wait()
            return True
        except Exception as e:
            # FIXME: log errors
            return False

    def sync_images(self, images=None):
        "Sync images on host"
        results = []
        all_lines = []
        if images is None:
            cmd = ["heaver-img", "-S", "--all", "--format=json"]
            _, proc = self._invoke(cmd)
            exit_code = proc.wait()
            stdout = proc.readlines_stdout()
            stderr = proc.readlines_stderr()
            if exit_code != 0:
                process_fail(cmd, exit_code, stdout, stderr) # raises
            all_lines = stdout
        else:
            for image in images:
                cmd = ["heaver-img", "-S", "-i", image, "--format=json"]
                _, proc = self._invoke(cmd)
                exit_code = proc.wait()
                stdout = proc.readlines_stdout()
                stderr = proc.readlines_stderr()
                if exit_code != 0:
                    process_fail(cmd, exit_code, stdout, stderr) # raises
                all_lines.extend(stdout)

        for line in all_lines:
            try:
                answer = json.loads(line)
            except:
                continue
            if answer["type"] == "result":
                results.append(answer["data"])

        return results


    def _get_executor(self):
        "Retrieve executor from pool"
        return self.pool.get_connection(self.hostname)

    def _execute_update(self, args):
        "Invoke command with status dump, update tracker"
        args = args + ["--status"]
        out = self._execute(args)
        if len(out) == 0:
            raise OperationError("Worker '%s' wont send status, punch him" % self.hostname)
        try:
            host = json.loads(out[-1])
        except:
            # FIXME: log errors
            raise OperationError("Status corrupted")
        logger.debug("got status: %s" % str(host))
        self.tracker.update_host(self.hostname, host["data"])
        return out[:-1]

    def _execute(self, args):
        "Invoke command and wait for it completion"
        full_args = ["heaver", "--format", "json"] + args # TODO: add verbosity
        cmd, proc = self._invoke(full_args)
        exit_code = proc.wait()
        if exit_code != 0:
            process_fail(cmd, exit_code, proc.readlines_stdout(),
                proc.readlines_stderr())
        return proc.readlines_stdout()

    def _invoke(self, args):
        "Invokes command"
        escaped_args = map(shellquote, args)
        cmd = " ".join(escaped_args)

        return cmd, self._try_invoke(cmd)

    def _try_invoke(self, cmd):
        "Invokes command to exec. If ssh connection stale, reconnects and retries"
        comm = None
        exc = None
        for i in xrange(SSH_RECONNECT_RETRIES):
            try:
                comm = self._get_executor().invoke(cmd)
                break
            except Exception as e:
                # reconnect and retry
                logger.warning("failed to open ssh session on host '%s' (attempt %d): %s" % (
                               self.hostname, i, str(e)))
                try:
                    self.pool.drop(self.hostname)
                except Exception as e:
                    logger.warning("failed to close ssh connection to host '%s': %s" % (
                        self.hostname, str(e)))
                exc = e
        else:
            # reconnects dont fix the problem
            logger.error(("failed to open ssh session on host '%s' (finally), giving up. "
                          "Last exception: %s") % (self.hostname, str(exc)))
            raise OperationError("Cannot open ssh session to host '%s'" % self.hostname)

        return comm

    def _try_invoke_sftp(self):
        "Invokes sftp subsystem. If ssh connection stale, reconnects and retries"
        sftp = None
        exc = None
        for i in xrange(SSH_RECONNECT_RETRIES):
            try:
                sftp = self._get_executor().invoke_sftp()
                break
            except Exception as e:
                # reconnect and retry
                logger.warning("failed to open sftp session on host '%s' (attempt %d): %s" % (
                               self.hostname, i, str(e)))
                try:
                    self.pool.drop(self.hostname)
                except Exception as e:
                    logger.warning("failed to close ssh connection to host '%s': %s" % (
                        self.hostname, str(e)))
                exc = e

        else:
            # reconnects dont fix the problem
            logger.error(("failed to open sftp session on host '%s' (finally), giving up. "
                          "Last exception: %s") % (self.hostname, str(exc)))
            raise OperationError("Cannot open sftp session to host '%s'" % self.hostname)

        return sftp


def stream_sftp_file(file, filename, sftp):
    "Yield file chunks, then close both file and sftp session"
    pos = 0
    edge = 0
    size = file.stat().st_size
    while True:
        if pos == size: # eof
            file.close()
            sftp.unlink(filename)
            sftp.close()
            return
        if pos >= edge:
            # mark up chunks for readahead
            edge, chunks = make_chunks(pos, size)
            # feed them to sftp
            reader = file.readv(chunks)
        # every call returns next designated chunk
        chunk = next(reader)
        yield chunk
        pos += len(chunk)

def make_chunks(pos, size):
    left = min(STREAM_BUFFER, size - pos)
    edge = pos + left
    read_chunks = []
    while left > 0:
        chunk_size = min(left, STREAM_CHUNK_SIZE)
        read_chunks.append((pos, chunk_size))
        pos += chunk_size
        left -= chunk_size

    return edge, read_chunks


def process_fail(cmd, exit_code, out, err):
    logger.error("Execution of '%s' has failed with code %d" % (cmd, exit_code))

    # find error messages, if any
    if out:
        for idx, line in enumerate(out):
            try:
                msg = json.loads(line)
                # FIXME: message format
            except:
                if msg.startswith("Traceback"):
                    # internal error
                    logger.error("Interal slave error, printing remote traceback")
                    for line in out[idx:]:
                        logger.error(line)
                        raise OperationError("Internal error")
            if isinstance(msg, dict) and msg.get("type") == "error":
                logger.error(msg["message"])
                raise OperationError(msg["message"])

    if err:
        logger.debug(" STDERR ".center(16, "-"))
        for line in err:
            logger.debug(line)

def shellquote(arg):
    return "'%s'" % arg.replace("'", "'\\''")
