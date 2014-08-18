import os
import stat
import subprocess
import string
import shutil
import copy
import datetime
import time
import math 
import multiprocessing

#__all__ = ["start", "stop"]

LXC_PATH = "/var/lib/lxc" # TODO: should be in config? In lxc-* just hardcoded


## docker's full cap drop. Will break mounts in containers
# DROPPED_CAPS = ["mknod", "sys_admin", "sys_boot", "sys_module", "sys_nice", "sys_pacct",
#   "sys_rawio", "sys_time", "sys_tty_config"]

# just forbid time travel
DROPPED_CAPS = ["sys_time"]

DEFAULT_CONFIG = dict(mounts=[
    "proc %(root)s/proc proc nosuid,nodev,noexec 0 0",
    "sysfs %(root)s/sys sysfs nosuid,nodev,noexec 0 0",
    "devpts %(root)s/dev/pts devpts newinstance,ptmxmode=0666,nosuid,noexec 0 0",
    ],
    networks=dict(
        # eth0=dict(type="veth", link="lxcbr0", flags="up", ips=[("192.168.100.2", "24")],
        #     gateway="auto"),
        ),
    raw={"pts": 1024,
        "cgroup.devices.deny": "a",
        "cgroup.devices.allow": ["c 1:3 rwm", "c 1:5 rwm", "c 5:0 rwm",
            "c 4:0 rwm", "c 1:8 rwm", "c 1:9 rwm", "c 136:* rwm",
            "c 5:2 rwm", "c 10:200 rwm", "c 10:229 rwm", "c 254:0 rwm"],
        "tty": 0,
        # comment if you dont want better isolation
        "cap.drop": " ".join(DROPPED_CAPS),
        "kmsg": 0,
        }
    )

DEV_MOUNTS = ["%(root)s/binds/dev %(root)s/dev none bind 0 0"]

## if you does not have appropriate apparmor profile and want mount isolation, use this:
# SYSTEMD_MOUNTS = ["%(root)s/binds/cgroup %(root)s/sys/fs/cgroup/ none bind 0 0",
#     ("none %(root)s/sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,"
#         "release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0")]
# ARCH_MOUNTS = ["run %(root)s/run tmpfs nosuid,nodev,noexec 0 0",
#     "shm %(root)s/dev/shm tmpfs nosuid,nodev,noexec 0 0"]

SYSTEMD_MOUNTS = []
ARCH_MOUNTS = []

DEFAULT_MOUNTS = dict(dev=[
        ("console", "c", ("5", "1", 0600)),
        ("full", "c", ("1", "7", 0666)),
        ("null", "c", ("1", "3", 0666)),
        ("pts", "d", None),
        ("random", "c", ("1", "8", 0666)),
        ("shm", "d", None),
        ("tty", "c", ("5", "0", 0666)),
        ("urandom", "c", ("1", "9", 0666)),
        ("zero", "c", ("1", "5", 0666)),
        ("fuse", "c", ("10", "229", 0666)),
    ])

DEFAULT_MOUNTS_DIR = "binds/"


class ContainerNotFound(Exception):
    pass

class ContainerExists(Exception):
    pass

class ContainerBusy(Exception):
    pass

class InvalidConfig(Exception):
    pass

class CreationError(Exception):
    pass

class StartError(Exception):
    pass

class InvocationError(Exception):

    def __init__(self, cmd, exit_code, stdout, stderr):
        self.cmd = cmd
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        if isinstance(self.cmd, list):
            escaped = ["'%s'" % part for part in self.cmd]
            cmd = " ".join(escaped)
        else:
            cmd = self.cmd
        out = ["Command failed!", " CMD ".center(15, "-"), cmd]
        if self.stdout:
            out.append(" STDOUT ".center(15, "-"))
            out.append(self.stdout)
        if self.stderr:
            out.append(" STDERR ".center(15, "-"))
            out.append(self.stderr)

        return "\n".join(out)


def start(name, inner_cmd=None):
    "Starts container"

    if exists(name):
        if is_running(name):
            return True

        cmd = ["systemctl", "start", "lxc@%s" % name]
        if inner_cmd:
            cmd.append(inner_cmd)
        config_path = get_box_home(name, "config")
        try:
            config = parse_lxc_config(config_path)
        except Exception as e: #FIXME: correct exceptions
            raise InvalidConfig(e)

        if not os.path.exists(config["root"]):
            raise StartError("Container root does not exist")

        try:
            make_startup_mounts(config)
        except Exception as e: #FIXME: correct exceptions
            #raise StartError(e)
            raise

        exit_code, stdout, stderr = exec_cmd(cmd)
        if exit_code != 0:
            raise InvocationError(cmd, exit_code, stdout, stderr)

        # TODO: use systemd or similar library for tracking state of lxc
        # check status
        
        MainPID = "0"
        start_timeout = 0 
        
        while MainPID == "0":
    	    exit_code, stdout, stderr = exec_cmd(["systemctl", "show", "-p", "MainPID", "lxc@%s" % name])
    	    MainPID = stdout.split("=")[1].replace('\n', '').replace(' ', '')
    	    start_timeout += 1

    	    if start_timeout==100:
    		# return info
    		exit_code, stdout, stderr = exec_cmd(["systemctl", "status", "lxc@%s" % name])
        	raise InvocationError(cmd, exit_code, stdout, stderr)

        return True

    else:
        raise ContainerNotFound(name)


def stop(name):
    "Stops container"

    if exists(name):
        cmd = ["systemctl", "stop", "lxc@%s" % name]
        exit_code, stdout, stderr = exec_cmd(cmd)
        if exit_code != 0:
            raise InvocationError(cmd, exit_code, stdout, stderr)

        # TODO: use systemd or similar library for tracking state of lxc
        # check status

        MainPID = "-1"
        start_timeout = 0 
        
        while MainPID != "0":
    	    exit_code, stdout, stderr = exec_cmd(["systemctl", "show", "-p", "MainPID", "lxc@%s" % name])
    	    MainPID = stdout.split("=")[1].replace('\n', '').replace(' ', '')
    	    start_timeout += 1

    	    if start_timeout==100:
    		# return info
    		exit_code, stdout, stderr = exec_cmd(["systemctl", "status", "lxc@%s" % name])
        	raise InvocationError(cmd, exit_code, stdout, stderr)

        return True


    else:
        raise ContainerNotFound(name)


def create(name, cont_config):
    "Create container"
    if exists(name):
        raise ContainerExists(name)

    config = copy.deepcopy(DEFAULT_CONFIG)

    if "root" not in cont_config:
        raise InvalidConfig("No root in config")

    root = cont_config["root"]
    try:
        if "mounts" in cont_config:
            config["mounts"].extend(cont_config.pop("mounts"))
        if "raw" in cont_config:
            config["raw"].update(cont_config.pop("raw"))
        if "networks" in cont_config:
            config["networks"].update(cont_config.pop("networks"))
        config.update(cont_config)
    except Exception as e:
        raise InvalidConfig("Failed to merge configs: %r" % e)

    if "hostname" not in config:
        config["hostname"] = name

    # insert /dev bindmount first for all
    config["mounts"] = DEV_MOUNTS + config["mounts"]

    # distro-specific mounts
    distro = detect_distro(config["root"])
    if distro == "arch":
        # add cgroup/systemd mounts, if missing
        def has_cgroup(mount):
            return "cgroup/systemd" in mount #FIXME: proper fstab detection
        systemd_cgroup = filter(has_cgroup, config["mounts"])
        if not systemd_cgroup:
            config["mounts"].extend(SYSTEMD_MOUNTS)

        # arch-specific mounts
        config["mounts"].extend(ARCH_MOUNTS)

    try:
        lxc_config = make_lxc_config(name, config)
    except Exception as e:
        raise InvalidConfig(e)

    cont_dir = get_box_home(name)
    try:
        os.mkdir(cont_dir)
    except Exception as e: # TODO: correct exception type
        raise CreationError("Cannot make dir for container: %r" % e)

    conffile_path = os.path.join(cont_dir, "config")
    try:
        conffile = open(conffile_path, "w")
        conffile.write(lxc_config)
        conffile.close()
    except Exception as e: #TODO: correct exception type
        raise CreationError("Cannot create config: %r" % e)

    # write ssh key for root, if needed
    if cont_config["key"] is not None:
        root_ssh = os.path.join(config["root"], "root", ".ssh")
        if not os.path.isdir(root_ssh):
            try:
                os.makedirs(root_ssh)
            except Exception as e:
                raise CreationError("Cannot create dirs for ssh key: %r" % e)
        try:
            auth_keys_file = open(os.path.join(root_ssh, "authorized_keys"), "a")
            auth_keys_file.write("# added by heaver for container '%s'\n" % name)
            auth_keys_file.write(cont_config["key"].strip())
            auth_keys_file.write("\n")
            auth_keys_file.close()
        except Exception as e:
            raise CreationError("Cannot write down ssh key: %r" % e)

    return True


def destroy(name):
    "Destroy stopped container"
    if not exists(name):
        raise ContainerNotFound(name)

    if is_running(name):
        raise ContainerBusy("Container '%s' still running" % name)

    path = get_box_home(name)
    try:
        umount_subs(path)
        shutil.rmtree(path) # can raise (but what?)
    except:
        pass #FIXME: handle exceptions


def ls():
    "Retrieve list of all containers"
    all_conts = [d for d in os.listdir(LXC_PATH) if os.path.isdir(os.path.join(LXC_PATH, d))]
    exit_code, stdout, stderr = exec_cmd(["lxc-ls", "--active", "-1"])
    if exit_code != 0:
        raise InvocationError(cmd, exit_code, stdout, stderr)
    all_active = stdout.split("\n")

    status = dict()
    for cont in all_conts:
        cont_status = dict()
        if cont in all_active:
            cont_status["active"] = True
        else:
            cont_status["active"] = False

        config = get_box_config(cont)
        dev_ips = dict()
        for device, network in config["networks"].items():
            dev_ips[device] = []
            for ip, mask in network["ips"]:
                dev_ips[device].append("%s/%s" % (ip, mask))
        cont_status["ips"] = dev_ips

        status[cont] = cont_status

    return status


def write_tarball(name, fileobj):
    try:
        config = get_box_config(name)
        root = config["root"]
    except Exception as e:
        raise InvalidConfig("invalid container config: %s" % e)

    if not os.path.exists(root):
        raise InvalidConfig("root of container '%s' does not exist ('%s')" % (name, root))

    cmd = ["tar", "c", "--numeric-owner", "-C", root, "."]
    process = subprocess.Popen(cmd, stdout=fileobj, stderr=subprocess.PIPE)
    _stdout, stderr = process.communicate()
    exit_code = process.returncode
    if exit_code > 0:
        raise InvocationError(cmd, exit_code, _stdout, stderr)


def exec_cmd(cmd, stdin=""):
    "Execute given cmd and optionally stdin, return exit code, stdout, stderr"
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(stdin)
    exit_code = process.returncode

    return exit_code, stdout, stderr

def umount_subs(root):
    "Umount all mounts from given root path"
    pass #FIXME: unstub


def exists(name):
    "Check if container with given name already exists"
    path = get_box_home(name)
    return os.path.isdir(path)


def is_running(name):
    "Check if container already running"
    if not exists(name):
        return False

    cmd = ["lxc-ls", "--active", "-1"] # TODO: reimplement lxc-ls
    exit_code, stdout, stderr = exec_cmd(cmd)
    if exit_code == 0:
        names = stdout.split("\n")
        return name in names
    elif exit_code == 1:
        return False
    else:
        raise InvocationError(cmd, exit_code, stdout, stderr)


def detect_distro(root):
    if os.path.exists(os.path.join(root, "etc", "arch-release")):
        return "arch"
    lsb_release = os.path.join(root, "etc", "lsb-release")
    if os.path.exists(lsb_release):
        try:
            lines = open(lsb_release).read().split("\n")
        except:
            return "unknown"

        dist_id = None
        dist_name = None
        for line in lines:
            if "DISTRIB_ID" in line:
                dist_id = line.partition("=")[2]
            if "DISTRIB_CODENAME" in line:
                dist_name = line.partition("=")[2]

        if dist_id:
            if dist_name:
                return "%s-%s" % (dist_id, dist_name)
            else:
                return dist_id
        else:
            return "unknown"

    return "unknown"


def make_chardev(path, opts):
    old_umask = os.umask(0)
    major, minor = int(opts[0]), int(opts[1])
    mode = int(opts[2])

    if os.path.exists(path):
        fstat = os.stat(path)
        if not hasattr(fstat, "rdev"):
            os.unlink(path)
        elif (major, minor) != (os.major(fstat.rdev), os.minor(fstat.rdev)):
            os.unlink(path)
    if not os.path.exists(path):
        os.mknod(path, mode | stat.S_IFCHR, os.makedev(major, minor))
    os.umask(old_umask)


def make_startup_mounts(config):
    "Make needed mount sources"
    root = config["root"]

    binds_root = os.path.join(root, DEFAULT_MOUNTS_DIR)
    if not os.path.exists(binds_root):
        os.mkdir(binds_root)

    # dev
    devdir = os.path.join(root, DEFAULT_MOUNTS_DIR, "dev")

    if not os.path.exists(devdir):
        os.mkdir(devdir)

    for name, type, opts in DEFAULT_MOUNTS.get("dev", []):
        path = os.path.join(devdir, name)

        if type == "c":
            make_chardev(path, opts)
        elif type == "d":
            if not os.path.exists(path):
                os.mkdir(path)

    # cgroup/systemd, if needed
    def has_cgroup(mount):
        return "cgroup/systemd" in mount #FIXME: proper detection of mounts

    systemd_cgroup = filter(has_cgroup, config["mounts"])
    if systemd_cgroup:
        cgroup_path = os.path.join(root, DEFAULT_MOUNTS_DIR, "cgroup")
        if not os.path.exists(cgroup_path):
            os.mkdir(cgroup_path)
        systemd_path = os.path.join(cgroup_path, "systemd")
        if not os.path.exists(systemd_path):
            os.mkdir(systemd_path)


def parse_lxc_config(path):
    "Parses lxc config"
    lines = open(path).read().split("\n")
    config = dict(mounts=list(), raw=dict(), networks=dict(), limits=dict())

    current_net = None
    for line in lines:
        # remove comments and surrounding whitespaces
        if line.find("#") != -1:
            sub = line[:line.find("#")].strip()
        else:
            sub = line.strip()

        if sub:
            if not sub.startswith("lxc."):
                # TODO: malformed line? Maybe raise somewhat?
                pass
            else:
                name, _delimeter, value = sub.partition("=")
                name = name.strip()[4:]
                value = value.strip()
                if not name or not value:
                    # TODO: malformed value? Maybe raise somewhat? [2]
                    pass
                else:
                    if name == "rootfs":
                        config["root"] = value
                    elif name == "utsname":
                        config["hostname"] = value
                    elif name == "mount.entry":
                        config["mounts"].append(value)
                    elif name.startswith("network."):
                        net_name = name[8:]
                        if net_name == "type":
                            if current_net:
                                device = current_net.pop("device", "")
                                # if no device specified, it is empty or malformed record
                                if device:
                                    config["networks"][device] = current_net

                            current_net = dict(type=value, ips=[])
                        elif net_name == "name":
                            current_net["device"] = value
                        elif net_name == "flags":
                            current_net["flags"] = value
                        elif net_name == "link":
                            current_net["link"] = value
                        elif net_name == "ipv4":
                            current_net["ips"].append(value.split("/", 1))
                        elif net_name == "ipv4.gateway" and value is not None:
                            current_net["gateway"] = value
                    # limits
                    elif name.startswith("cgroup.cpu"):
                        if name == "cgroup.cpu.cfs_quota_us":
                            config["cpu"] = float(value) / 100000
                    elif name.startswith("cgroup.memory"):
                        if name == "cgroup.memory.limit_in_bytes":
                            config["memory"] = value
                    # raw values
                    else:
                        if name == "cgroup.devices.allow":
                            config["raw"].setdefault("cgroup.devices.allow", []).append(value)
                        else:
                            config["raw"][name] = value

    # parse datamounts
    datamounts = list()
    root = config["root"]
    # make a copy of "mounts" since we can remove some items in loop
    for mount in list(config["mounts"]):
        source, dest, mount_type, mount_opts, _rest = string.split(mount, maxsplit=4)
        if mount_type == "datamount" and "bind" in mount_opts:
            if not dest.startswith(config["root"]):
                raise Exception("datamount outside root: '%s'" % mount)

            config["mounts"].remove(mount)
            # strip root from mountpoint
            mountpoint = dest[len(config["root"]):]
            if mountpoint[0] != "/":
                mountpoint = "/" + mountpoint

            datamounts.append((mountpoint, source))
    config["datamounts"] = datamounts

    if current_net:
        device = current_net.pop("device", "")
        # if no device specified, it is empty or malformed record
        if device:
            config["networks"][device] = current_net
    return config


def make_lxc_config(name, config):
    lines = []

    lines.append("# Config for container '%s'" % name)
    lines.append("# Generated by heaver, %s" % datetime.datetime.now())

    # basic options
    lines.append("lxc.utsname = %(hostname)s" % config)
    lines.append("lxc.rootfs = %(root)s" % config)
    lines.append("lxc.aa_profile = lxc-container") #FIXME: detect that profile exists on host
    lines.append("lxc.console = %s" % get_box_home(name, "console"))

    lines.append("")

    # mounts
    lines.append("# mounts")
    for mount in config["mounts"]:
        full_mount = mount % config # substitute root
        lines.append("lxc.mount.entry = %s" % full_mount)

    # datamounts
    if "datamounts" in config:
        lines.append("# datamounts")
        for mountpoint, source in config["datamounts"]:
            # hackish mount definition. Since mount type is 'bind' it fs type may
            # be anything we want
            mountpoint = mountpoint.lstrip("/")
            mount_str = "%s %s datamount bind 0 0" % (source, os.path.join(config["root"],
                                                                           mountpoint))
            lines.append("lxc.mount.entry = %s" % mount_str)
    lines.append("")

    # network config
    lines.append("# net devices")
    if not config.get("networks", None):
        lines.append("lxc.network.type = empty") # for isolation when no networks defined
        lines.append("")
    for dev, net_config in config["networks"].items():
        lines.append("lxc.network.type = %(type)s" % net_config)
        lines.append("lxc.network.link = %(link)s" % net_config)
        lines.append("lxc.network.name = %s" % dev)
        lines.append("lxc.network.flags = %(flags)s" % net_config)
        if "hwaddr" in net_config:
            lines.append("lxc.network.hwaddr = %s" % net_config["hwaddr"])
        for addr_mask in net_config["ips"]:
            lines.append("lxc.network.ipv4 = %s/%s" % addr_mask)
        if net_config.get("gateway"):
            lines.append("lxc.network.ipv4.gateway = %(gateway)s" % net_config)
        lines.append("")

    lines.append("")

    # limits
    lines.append("# limits")
    limits = config["limits"]
    cpu_limit = limits.get("cpu")
    if cpu_limit is not None:
        lines.append("lxc.cgroup.cpu.cfs_period_us = 100000")
        lines.append("lxc.cgroup.cpu.cfs_quota_us = %d" % int(float(cpu_limit) * 100000))

        # get count of using cpus
        using_cpu_count = int(math.ceil(cpu_limit))
        # get total cpu count
        actual_cpu_count = multiprocessing.cpu_count()
        # initiate cpu usage dict
        
        # using cpus cannot be larger then actual 
        if using_cpu_count >= actual_cpu_count:
            using_cpu_count = actual_cpu_count - 1

        cpu_usage = {x:0 for x in range(actual_cpu_count)}
        try:
            cpu_usage_file = open("/var/lib/heaver/used_cpu", "r").read().split("\n")
            c = 0
            for cpu in cpu_usage_file:
                # restore cpu usage table
                cpu_num, cpu_load = cpu.split(":")
                cpu_usage[int(cpu_num)] = int(cpu_load)
                # cpu counter
                c += 1
        except:
            # cpu usage file may not exists, so cpu table is empty
            pass
            
	reserve_cpu = limits.get("reserve_cpu")
	# remove resered cpu from list
	if reserve_cpu is not None:
	    cpu_usage.pop(int(reserve_cpu))
	
	sorted_by_load_cpu = sorted(cpu_usage.items(), key=lambda x: x[1])
	using_cpus = []
	for i in range(using_cpu_count):
	    cpu_usage[sorted_by_load_cpu[i][0]] += 1
	    using_cpus.append(sorted_by_load_cpu[i][0])
	
	
	lines.append("lxc.cgroup.cpuset.cpus = %s" % ",".join(str(n) for n in using_cpus))


        cpu_usage[int(reserve_cpu)] = 100500
        cpu_usage_file = open("/var/lib/heaver/used_cpu", "w")
        c = 0
        # store cpu usage table
        for cpu in cpu_usage:
            cpu_usage_file.write("%d:%d\n" % (cpu,cpu_usage[cpu]))
            # cpu counter
            c += 1
        
        cpu_usage_file.close()
        
            
        
    memory_limit = limits.get("memory")
    if memory_limit is not None:
        lines.append("lxc.cgroup.memory.limit_in_bytes = %s" % memory_limit)

    lines.append("")
    # raw values
    lines.append("# raw lxc config values")
    for key, value in config.get("raw", {}).items():
        if isinstance(value, list):
            for subvalue in value:
                lines.append("lxc.%s = %s" % (key, str(subvalue)))
        else:
            lines.append("lxc.%s = %s" % (key, str(value)))

    return "\n".join(lines)


def get_box_config(name):
    "Retrieve box config by it name"
    config_file = get_box_home(name, "config")
    config = parse_lxc_config(config_file)
    return config

def get_box_home(name, *sub_paths):
    "Return path, when box's configs reside (not root)"
    return os.path.join(LXC_PATH, name, *sub_paths)
