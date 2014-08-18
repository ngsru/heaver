import socket
import select
import paramiko


class Communicator(object):
    "Implements communication with remote process"

    def __init__(self, chan):
        self._chan = chan
        self._stdin = chan.makefile("wb")

        self._stdout = chan.makefile("rb")
        self._stdout_lines = []
        self._stdout_eof = False

        self._stderr = chan.makefile_stderr("rb")
        self._stderr_lines = []
        self._stderr_eof = False

        self.exit_code = None

        chan.setblocking(0)

    #TODO: timeouts, connection errors handling
    def _read_chunk(self):
        "Wait for activity in channel and read both stdout and stderr lines from it"
        rfd, wfd, efd = select.select([self._chan], [], [])

        stdout_chunk, stdout_eof = consume_lines(self._stdout)
        stderr_chunk, stderr_eof = consume_lines(self._stderr)

        self._stdout_lines.extend(stdout_chunk)
        self._stderr_lines.extend(stderr_chunk)

        self._stdout_eof = stdout_eof
        self._stderr_eof = stderr_eof

    def readline_stdout(self):
        "Read line from process stdout"
        while len(self._stdout_lines) == 0 and not self._stdout_eof:
            self._read_chunk()

        if len(self._stdout_lines) == 0 and self._stdout_eof:
            return None
        return self._stdout_lines.pop(0)

    def readline_stderr(self):
        "Read line from process stderr"
        while len(self._stderr_lines) == 0 and not self._stderr_eof:
            self._read_chunk()

        if self._stderr_eof:
            return None
        return self._stderr_lines.pop(0)

    def readlines_stdout(self):
        "Read all lines from process stdout until eof (when process finishes or closes it stdout)"
        while not self._stdout_eof:
            self._read_chunk()
        lines = self._stdout_lines
        self._stdout_lines = []
        return lines

    def readlines_stderr(self):
        "Read all lines from process stderr until eof (when process finishes or closes it stderr)"
        while not self._stderr_eof:
            self._read_chunk()
        lines = self._stderr_lines
        self._stderr_lines = []
        return lines

    def wait(self):
        "Wait for process completion, return exit code"
        self.exit_code = self._chan.recv_exit_status()
        return self.exit_code


class Executor(object):
    "Helper class for executing commands through ssh connection"

    def __init__(self, transport):
        self.transport = transport

    def __del__(self):
        self.close()

    def execute(self, cmd, input=None): # TODO: timeouts?
        "Execute cmd and return stdin, stdout, exit code"
        proc = self.invoke(cmd)
        if input:
            proc.stdin.write(input)

        stdout = proc.readlines_stdout()
        stderr = proc.readlines_stderr()
        exit_code = proc.wait()

        return stdout, stderr, exit_code

    def invoke(self, cmd):
        "Invoke cmd, attach to its stdin, stdout, stderr and give control over it"
        chan = self.transport.open_session()
        chan.exec_command(cmd)

        return Communicator(chan)

    def invoke_sftp(self):
        "Invoke sftp subsystem, return paramiko's SFTPClient"
        return paramiko.SFTPClient.from_transport(self.transport)

    def close(self):
        "Close this ssh session"
        self.transport.close()


def connect(host, username, key_filename):
    "Establishes ssh2 connection to host"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # handle errors outside
    sock.connect((host, 22)) #TODO: parse port from host?

    transport = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client()
        key = paramiko.RSAKey.from_private_key_file(key_filename)
        transport.auth_publickey(username, key)
        if not transport.is_authenticated():
            raise paramiko.SSHException("Invalid key")
    except Exception as e:
        if transport:
            transport.close()
        sock.close()
        raise

    return Executor(transport)


def consume_lines(source):
    "Read all available lines from non-blocking socket"
    lines = []
    while True:
        try:
            line = source.readline()
            if line == "": # EOF
                return lines, True
            else:
                lines.append(line)
        except socket.timeout:
            return lines, False
