
import sys
import os
import random
import time

import heaver.ops as ops
import heaver.addrpool as addrpool
import heaver.cli.report as report
import heaver.utils as utils
import heaver.image as image
import heaver.client as client

HEAVER_TMPDIR = "/var/lib/heaver/tmp"
NETWORK_TYPES = ["bridge"]

def main(args, config):

    actions = [args.start, args.create, args.stop, args.destroy, args.list, args.tarball,
               args.send_status, args.status, args.startup, args.shutdown]
    if not any(actions):
        report.die("No action given")

    if args.start and args.stop: #TODO: can act as restart
        report.die("Cannot start and stop container simultaneously (-ST given)")

    if args.create and args.destroy:
        report.die("Cannot create and destroy container simultaneously (-CD given)")

    if (not args.name and not args.all and not args.send_status and not args.status
        and not args.list and not args.startup and not args.shutdown):
        report.die("No container chosen (no -n or --all options)")

    if args.create:
        create(args, config)

    if args.start:
        start(args, config)

    if args.stop:
        stop(args, config)

    if args.destroy:
        destroy(args, config)

    if args.list:
        list_(args, config)

    if args.tarball:
        make_tarball(args, config)

    if args.send_status:
        send_status(args, config)

    if args.status:
        status(args, config)

    if args.startup:
        startup(args, config)

    if args.shutdown:
        shutdown(args, config)


def create(args, config):
    must_be_root()
    if not args.name:
        report.die("No container chosen (create cannot be feed with --all)")
    if ops.exists(args.name):
        report.die("Container %s already exists" % args.name)

    if not args.root and not args.image:
        report.die("Either image or root must be given (-i or -r)")

    if "limits" not in config:
        report.die("No \"limits\" section in config")

    must_be_correct_limits_config(config["limits"])
    if args.limit is not None and len(args.limit) > 0:
        for limit in args.limit:
            name, _delim, value = limit.partition("=")
            config["limits"][name] = value
        # recheck config
        must_be_correct_limits_config(config["limits"])

    key = None
    if args.key:
        try:
            with open(args.key) as key_file:
                key = key_file.read()
        except Exception as e:
            report.die("Cannot read given key file: %s" % e)
    elif args.raw_key:
        key = args.raw_key

    root_generated = False
    data_mounts = []
    if args.root:
        root = args.root
    else:
        imager = image.get_image_operator(config["image"])
        try:
            images = []
            for img_arg in args.image:
                images.append(img_arg.split(":")[0])
            status = imager.sync_images(images)
            for img_name, img_status in status:
                if img_status == "error":
                    report.die("Cannot sync image '%s'" % img_name)
            # find root image (it's without additional path)
            root_images = filter(lambda img: not ":" in img or img.endswith(":/"), args.image)
            if len(root_images) == 0:
                report.die("No root image specified")

            if len(root_images) > 1:
                report.die("Only one root image may be used")
            root_image = root_images[0].split(":")[0]
            root = imager.create_instance(root_image, args.name)

            data_images = list(args.image)
            data_images.remove(root_images[0])

            for data_image in data_images:
                image_name, _semicolon, mountpoint = data_image.partition(":")
                data_root = imager.create_instance(image_name, args.name)
                data_mounts.append((mountpoint, data_root))

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            report.die("Cannot acquire root with image id '%s': %s\n%s" % (args.image, e, tb))
        root_generated = True

    if root[0] != "/":
        root = os.path.join(os.getcwd(), root)

    box_config = dict(root=root, networks=dict(), key=key, datamounts=data_mounts)
    # set up limits

    box_config["limits"] = config["limits"]
    box_config["raw"] = dict()
    if "cgroup" in config:
        for name, value in config["cgroup"].items():
            if name == "cpuset.cpus" and value == "auto":
                value = get_balanced_cpu()
            box_config["raw"]["cgroup." + name] = value

    # set up network
    all_ips = []
    if args.net is None:
        must_be_correct_net_config(config["net"])
        used_ranges = utils.sync_open(config["net"]["used_ranges_path"], "a+")
        networks = must_load_net_config(config["net"]["networks"],
                                        used_ranges.read().strip().split())
        args.net = [networks.items()[0][1]["bridge"]]
        used_ranges.close()

    if args.net or args.raw_net:
        must_be_correct_net_config(config["net"])
        used_ranges = utils.sync_open(config["net"]["used_ranges_path"], "a+")
        networks = must_load_net_config(config["net"]["networks"],
                                        used_ranges.read().strip().split())
        bridge_count = 0
        if args.raw_net is not None:
            bridge_count = len(args.raw_net)
            for idx, net in enumerate(args.raw_net):
                bridge, hwaddr, ips = must_parse_net_arg(net)
                for ip, mask in ips:
                    all_ips.append(ip)
                net_config = dict(type="veth", ips=ips, link=bridge, flags="up")
                if hwaddr:
                    net_config["hwaddr"] = hwaddr
                if idx == 0:
                    net_config["gateway"] = "auto"
                box_config["networks"]["eth%d" % idx] = net_config
        if args.net is not None:
            for idx, net in enumerate(args.net):
                net_idx = idx + bridge_count
                name, _semicolon, ip_count_str = net.partition(":")
                if name not in networks:
                    report.die("No such network: %s" % name)
                if ip_count_str != "":
                    try:
                        ip_count = int(ip_count_str)
                    except:
                        report.die("Ip count for network '%s' is not an int" % name)
                else:
                    ip_count = 1

                network = networks[name]
                hwaddr, ips = must_gen_net(network, ip_count)
                for ip, mask in ips:
                    all_ips.append(ip)
                bridge = network["bridge"]
                if net_idx == 0:
                    gateway = network.get("gateway")
                else:
                    gateway = None
                net_config = dict(type="veth", ips=ips, link=bridge, flags="up", gateway=gateway,
                                  hwaddr=hwaddr)
                box_config["networks"]["eth%d" % net_idx] = net_config

        # overwrite config
        used_ranges.truncate(0)
        used_ranges.write("\n".join(networks.values()[0]["pool"].dump_used_ranges()))
        used_ranges.write("\n") # trailing newline
        used_ranges.close()
    try:
        ops.create(args.name, box_config)
    except ops.InvalidConfig as e:
        report.die("Internal error, invalid config: %r" % e)

        import traceback
        print traceback.format_exc()

        if all_ips:
            try:
                free_addresses(config["net"]["used_ranges_path"], all_ips)
            except e:
                report.die("Failed to free addresses, do it yourself: %s" % e)
    except ops.CreationError as e:
        report.die("Cannot create container: %r" % e)

    except Exception as e:
        import traceback
        report.die("!!! Unhandled exception !!!\n%s\n%s" % (traceback.format_exc(), e))

    # if root was generated, remember it
    if root_generated:
        root_gen_path = ops.get_box_home(args.name, "heaver_root_generated")
        try:
            open(root_gen_path, "w").close()
        except Exception as e:
            pass #FIXME: warn user about it

    msg = dict(status="OK", action="create", id=args.name)
    if all_ips:
        msg["message"] = "Created container %s with addresses: %s" % (args.name,
            ", ".join(all_ips))
        msg["data"] = dict(ips=all_ips)
    else:
        msg["message"] = "Created container %s" % args.name
    
    # send status to upstream if possible
    send_status_soft(args, config)

    print report.format(msg)


def start(args, config):
    must_be_root()
    names = must_get_names(args)

    # start
    for name in names:
        try:
            try:
                box_config = ops.get_box_config(name)
            except Exception as e:
                report.die("Cannot load '%s' config, is it broken? %s" % (name, e))
            if os.path.exists(ops.get_box_home(name, "heaver_root_generated")):
                imager = image.get_image_operator(config["image"])
                imager.assemble_instance(box_config["root"])

                if box_config["datamounts"]:
                    root = box_config["root"]
                    for mountpoint, source in box_config["datamounts"]:
                        imager.assemble_instance(source)
                        # since 'mountpoint' starts with / we need to remove it
                        mountpoint = mountpoint.lstrip("/")
                        mount_path = os.path.join(root, mountpoint)
                        if not os.path.exists(mount_path):
                            os.makedirs(mount_path)

            ops.start(name)
        except ops.InvocationError as e:
            report.die("LXC is broken, cannot start container %s: %s" % (name, e))
        except ops.ContainerNotFound as e:
            report.die("Container %s just disappeared, panic!" % name)
        try:
            running_flag = ops.get_box_home(name, "heaver_box_running")
            open(running_flag, "w").close()
        except Exception as e:
            pass # FIXME: should not happen, warn user/log?

	send_status_soft(args, config)
        print report.format(dict(status="OK", action="start", id=name,
            message="Container %s started" % name))


def stop(args, config):
    must_be_root()
    names = must_get_names(args)
    for name in names:
        try:
            ops.stop(name)
            try:
                box_config = ops.get_box_config(name)
            except Exception as e:
                report.die("Cannot load '%s' config, is it broken? %s" % (name, e))
            if os.path.exists(ops.get_box_home(name, "heaver_root_generated")):
                imager = image.get_image_operator(config["image"])
                if box_config["datamounts"]:
                    for mountpoint, source in box_config["datamounts"]:
                        imager.disassemble_instance(source)
                imager.disassemble_instance(box_config["root"])
        except ops.InvocationError as e:
            report.die("LXC is broken, cannot stop container %s: %s" % (name, e))
        except ops.ContainerNotFound as e:
            report.die("Container %s just disappeared, panic!" % name)
        try:
            running_flag = ops.get_box_home(name, "heaver_box_running")
            if os.path.exists(running_flag):
                os.unlink(running_flag)
        except Exception as e:
            pass # FIXME: should not happen, warn user/log?
	send_status_soft(args, config)
        print report.format(dict(status="OK", action="stop", id=name,
            message="Container %s stopped" % name))


def destroy(args, config):
    must_be_root()
    names = must_get_names(args)
    if args.all and not args.force:
        msg = ["Selected containers: %s" % ", ".join(names),
               "Are you sure to destroy all these (probably innocent) containers? [y/N] "]
        decision = raw_input("\n".join(msg))
        if not (decision.lower() == "y" or decision.lower() == "yes"):
            print "Okay"
            return

    for name in names:
        box_root = None
        if not ops.exists(name):
            print report.format(dict(status="OK", action="destroy", id=name,
                message="Container %s already destroyed" % name))
            continue
        try:
            box_config = ops.get_box_config(name)
        except Exception as e:
            report.die("Cannot load '%s' config, is it broken? %s" % (name, e))

        root_generated = os.path.exists(ops.get_box_home(name, "heaver_root_generated"))
        root = box_config.get("root")
        try:
            # Free addresses, associated with box
            ips = []
            for network in box_config["networks"].values():
                for ip, mask in network["ips"]:
                    ips.append(ip)
            free_addresses(config["net"]["used_ranges_path"], ips)
        except Exception as e:
            print "Cannot release assigned to box addresses:", e

            import traceback
            print traceback.format_exc()

        try:
            ops.destroy(name)
        except ops.ContainerBusy as e:
            report.die("Container busy: %s" % e)
        except ops.ContainerNotFound:
            pass
        except ops.InvocationError as e:
            report.die("LXC is broken, cannot destroy container %s: %s" % (name, e))

        # remove root, if it was generated
        if root_generated:
            imager = image.get_image_operator(config["image"])
            try:
                imager.destroy_instance(root)
            except Exception as e:
                report.die("Cannot remove root of container '%s': %s" % (name, e))
            if box_config["datamounts"]:
                for mountpoint, source in box_config["datamounts"]:
                    try:
                        imager.destroy_instance(source)
                    except Exception as e:
                        report.die("Cannot remove datamount '%s' in container'%s': %s" % (source,
                                                                                          name, e))
        send_status_soft(args, config)
        print report.format(dict(status="OK", action="destroy", id=name,
            message="Container %s destroyed" % name))


def list_(args, config):
    if args.name:
        all_boxes = ops.ls()
        if args.name not in all_boxes:
            report.die("No such container: '%s'" % args.name)
        boxes = {args.name: all_boxes[args.name]}
    else:
        boxes = ops.ls()
    print report.format(dict(status="OK", action="list", data=boxes, message=format_list(boxes)))


def make_tarball(args, config):
    must_be_root()
    if not args.name:
        report.die("No container chosen (tarball cannot be feed with --all)")

    name = args.name
    if name not in ops.ls():
        report.die("No such container: '%s'" % name)

    if ops.is_running(name):
        report.die("Container '%s' must be stopped for tarballing" % name)

    tar_path = args.tarball
    if tar_path == "<generated>":
        # make temporary path for tarball
        import tempfile
        try:
            tar_fd, tar_path = tempfile.mkstemp(dir=HEAVER_TMPDIR, prefix="%s.tar." % name)
            tar_file = os.fdopen(tar_fd, "w")
        except Exception as e: # FIXME: proper exceptions?
            report.die("Cannot create tarball of container '%s': '%s'" % (name, e))
    else:
        try:
            tar_file = open(tar_path, "wb")
        except Exception as e: # FIXME: proper exceptions?
            # cannot open file - no directory or no write access
            report.die("Cannot create tarball of container '%s': %s" % (name, e))

    box_config = ops.get_box_config(name)
    imager = image.get_image_operator(config["image"])
    imager.assemble_instance(box_config["root"])
    try:
        ops.write_tarball(name, tar_file)
    except Exception as e: # FIXME: proper exceptions?
        tar_file.close()
        os.unlink(tar_path)
        report.die("Cannot create tarball of container '%s': %s" % (name, e))

    tar_file.close()
    print report.format(dict(status="OK", action="tarball", data=tar_path,
        message="Tarball of container '%s' created at '%s'" % (name, tar_path)))


def startup(args, config):
    must_be_root()
    unset_cgroup_hierarchy()
    names = ops.ls()

    for name in names:
        running_flag = ops.get_box_home(name, "heaver_box_running")
        if os.path.exists(running_flag):
            try:
                try:
                    box_config = ops.get_box_config(name)
                except Exception as e:
                    report.die("Cannot load '%s' config, is it broken? %s" % (name, e))
                if os.path.exists(ops.get_box_home(name, "heaver_root_generated")):
                    imager = image.get_image_operator(config["image"])
                    imager.assemble_instance(box_config["root"])

                    if box_config["datamounts"]:
                        root = box_config["root"]
                        for mountpoint, source in box_config["datamounts"]:
                            imager.assemble_instance(source)
                            # since 'mountpoint' starts with / we need to remove it
                            mountpoint = mountpoint.lstrip("/")
                            mount_path = os.path.join(root, mountpoint)
                            if not os.path.exists(mount_path):
                                os.makedirs(mount_path)
                ops.start(name)
            except ops.InvocationError as e:
                report.die("LXC is broken, cannot start container %s: %s" % (name, e))
            except ops.ContainerNotFound as e:
                # WTF? Should not happen (containers in ops.ls() already exists)
                report.die("Container %s just disappeared, panic!" % name)
            
            send_status_soft(args, config)
            print report.format(dict(status="OK", action="startup", id=name,
                message="Container %s started after boot" % name))


def shutdown(args, config):
    must_be_root()
    names = ops.ls()

    for name in names:
        if ops.is_running(name):
            try:
                ops.stop(name)
                try:
                    box_config = ops.get_box_config(name)
                except Exception as e:
                    report.die("Cannot load '%s' config, is it broken? %s" % (name, e))
                if os.path.exists(ops.get_box_home(name, "heaver_root_generated")):
                    imager = image.get_image_operator(config["image"])
                    if box_config["datamounts"]:
                        for mountpoint, source in box_config["datamounts"]:
                            imager.disassemble_instance(source)
                    imager.disassemble_instance(box_config["root"])
            except ops.InvocationError as e:
                report.die("LXC is broken, cannot stop container %s: %s" % (name, e))
            except ops.ContainerNotFound as e:
                # WTF? Should not happen (containers in ops.ls() already exists)
                report.die("Container %s just disappeared, panic!" % name)

            send_status_soft(args, config)
            print report.format(dict(status="OK", action="shutdown", id=name,
                message="Container %s stopped at shutdown" % name))


def format_list(boxes):
    lines = []
    names = boxes.keys()
    if len(names) == 0:
        return ""

    padding = max(map(len, names))
    for name in sorted(names):
        dev_ips = []
        devs = sorted(boxes[name]["ips"].keys())
        for dev in devs:
            ips = boxes[name]["ips"][dev]
            dev_ips.append("%s: %s" % (dev, ", ".join(ips)))
        if dev_ips:
            lines.append("%s: %s, %s" % (name.rjust(padding),
                                         "active" if boxes[name]["active"] else "inactive",
                                         " ".join(dev_ips)))
        else:
            lines.append("%s: %s" % (name.rjust(padding),
                                     "active" if boxes[name]["active"] else "inactive"))
    return "\n".join(lines)


def send_status(args, config):
    if "upstream" not in config:
        report.die("Cannot send status to upstream - upstream isnt configured")

    c = client.Client(config["upstream"])
    status = get_status(config)

    answer = c.update_host(status["hostname"], status)
    # update authorized_keys file
    if "public_key" in answer:
        key = answer["public_key"]
        key_path = config.get("authorized_keys", os.path.expanduser("~/.ssh/authorized_keys"))
        update_authorized_keys(key, key_path)

    print report.format(dict(status="OK", action="send-status",
        message="Host status sent to daemon"))


# send status with silent return (w/o fail)
def send_status_soft(args, config):
    if "upstream" not in config:
        # Cannot send status to upstream - upstream isnt configured
        return

    try: 
        c = client.Client(config["upstream"])
        status = get_status(config)

        answer = c.update_host(status["hostname"], status)
        # update authorized_keys file
        if "public_key" in answer:
            key = answer["public_key"]
            key_path = config.get("authorized_keys", os.path.expanduser("~/.ssh/authorized_keys"))
            update_authorized_keys(key, key_path)

    except Exception as e:
        # connection failed
	return



def status(args, config):
    status = get_status(config)
    print report.format(dict(status="OK", action="status", data=status,
                             message=str(status)))


def get_status(config):
    if "hostname" in config:
        hostname = config["hostname"]
    else:
        import platform
        hostname = platform.node()

    status = dict(la=ops.get_la(), ram=ops.get_ram(), oom=ops.get_oom_stats(),
                  boxes=ops.ls(), hostname=hostname)
    used_ranges = utils.sync_open(config["net"]["used_ranges_path"], "a+")
    networks = must_load_net_config(config["net"]["networks"], used_ranges.read().strip().split())
    used_ranges.close()

    ips_free = 0
    for net in networks.values():
        ips_free += net["pool"].count_free_addresses()

    status["ips_free"] = ips_free

    imager = image.get_image_operator(config["image"])
    status["fs"] = imager.get_free_space()
    status["now"] = time.time()
    return status


def must_get_names(args):
    "Helper for retrieving container names"
    if args.all:
        try:
            names = ops.ls().keys()
        except ops.InvocationError as e:
            report.die("LXC is broken: %s" % e)
    else:
        if not ops.exists(args.name):
            report.die("No such container: %s" % args.name)

        names = [args.name]

    return names


def unset_cgroup_hierarchy():
    "Setup 0 to cgroup hierarchy"
    open("/sys/fs/cgroup/memory/memory.use_hierarchy", "w").write("0")
    # DIRTY PATCH
    # create reservation cgroup
    os.system("/usr/bin/cgcreate -a root -g memory,cpu:reservation")


def must_be_root():
    "Be superuser or die"
    if os.geteuid() != 0:
        report.die("Must be root")


def must_be_correct_net_config(config):
    "Check overall network setting and die if they are broken"
    # check that we can store used ranges
    if "used_ranges_path" not in config:
        report.die("\"used_ranges_path\" config value is missing in \"net\"")
    used_ranges_path = config["used_ranges_path"]
    if not isinstance(used_ranges_path, basestring):
        report.die("\"used_ranges_path\" must be string")
    if os.path.exists(used_ranges_path):
        if not os.access(used_ranges_path, os.W_OK):
            report.die("Used ranges file (%s) is not writeable" % used_ranges_path)
    elif not os.path.exists(os.path.dirname(used_ranges_path)):
        report.die(("Directory for used ranges file (%s) "
            "does not exist" % used_ranges_path))
    elif not os.access(os.path.dirname(used_ranges_path), os.W_OK):
            report.die(("Directory for used ranges file (%s) "
                "is not writeable" % used_ranges_path))

    networks = config.get("networks")
    if networks is None or not isinstance(networks, list):
        report.die("\"networks\" config value is missing in \"net\"")
    if len(networks) == 0:
        report.die("\"networks\" is empty. Configure at least one network")

    for idx, config in enumerate(networks):
        try:
            check_network_config(config)
        except Exception as e:
            report.die("malformed network config at index %d: %s" % (idx, e))


def must_be_correct_limits_config(config):
    "Check overall limits settings and die if they are broken"
    if not isinstance(config, dict):
        report.die("\"limits\" config not a dict")
    if "cpu" in config:
        cpu = config["cpu"]
        try:
            isinstance(cpu, float)
        except:
            report.die("\"limits.cpu\" setting is malformed")

    if "memory" in config:
        memory = config["memory"]
        if memory[-1] == "K" or memory[-1] == "M" or memory[-1] == "G":
            memory = memory[:-1]
        try:
            isinstance(memory, int)
        except:
            report.die("\"limits.memory\" setting is malformed")

    if "reserve_cpu" in config:
	reserve_cpu = config["reserve_cpu"]
        try:
            isinstance(reserve_cpu, int)
        except:
            report.die("\"limits.reserve_cpu\" setting is malformed")
	


def check_network_config(config):
    "Check one network configuration"
    # network configuration is a dict
    if not isinstance(config, dict):
        raise Exception("config must be a dict")

    # each network must have name and type
    name = config.get("name")
    if name is None or len(name) == 0:
        raise Exception("invalid name of network")

    ntype = config.get("type")
    if ntype not in NETWORK_TYPES:
        raise Exception("invalid network type")

    # each network must have list of assigned network ranges
    ranges = config.get("ranges")
    if ranges is None or not isinstance(ranges, list):
        raise Exception("invalid ranges definition")

    # check specific settings for each network type
    if ntype == "bridge":
        # bridge network type must have 'bridge' parameter which names existing
        # bridge device
        bridge_name = config.get("bridge")
        if bridge_name is None:
            raise Exception("\"bridge\" parameter is missing in bridged network")

        if not os.path.exists(os.path.join("/sys/class/net", bridge_name)):
            raise Exception("no such bridge device: '%s'" % bridge_name)
        elif not os.path.exists(os.path.join("/sys/class/net", bridge_name, "bridge")):
            raise Exception("not a bridge device: '%s'" % bridge_name)


def must_load_net_config(networks_config, used_ranges):
    "Read and parse network config or die"
    networks = dict()
    uranges = list()
    if len(networks_config) == 0:
        return dict()

    try:
        for config in networks_config:
            net = dict(type=config["type"], pool=addrpool.AddressPool(uranges),
                       gateway=config.get("gateway", "auto"))
            for r in config["ranges"]:
                net["pool"].add_range(r)

            if net["type"] == "bridge":
                net["bridge"] = config["bridge"]

            networks[config["name"]] = net
    except Exception as e:
        report.die("Invalid address range '%s' in config: %s" % (r, e))
    try:
        # all networks share same storage for used ranges, so any pool suffice
        pool = networks.values()[0]["pool"]
        for r in used_ranges:
            pool.add_used_range(r)
    except Exception as e:
        report.die("Invalid address range '%s' in used ranges: %s" % (r, e))

    return networks


def must_have_bridge(idx, config):
    "Die if haven't bridge for next network"
    if len(config["bridges"]) <= idx:
        report.die("Not enough bridges in config")
    return config["bridges"][idx]


def must_parse_net_arg(arg):
    "Helper for parsing net args"
    if ":" not in arg:
        report.die("No bridge interface supplied")
    br_conf, _colon, addrs_str = arg.partition(":")
    if "/" in br_conf:
        br_dev, _slash, hwaddr = br_conf.partition("/")
        hwaddr = hwaddr.replace(".", "").lower()
        if len(hwaddr) > 12:
            report.die("Hardware address is too long (must be 12 hex digits)")
        elif len(hwaddr) < 12:
            report.die("Hardware address is too short (must be 12 hex digits)")
        else:
            for idx, char in enumerate(hwaddr):
                if not ("0" <= char <= "9" or "a" <= char <= "f"):
                    report.die(("Invalid character in hardware address "
                        "at position %d (only hex digits allowed)") % idx)

    else:
        br_dev = br_conf
        hwaddr = None

    if not os.path.exists(os.path.join("/sys/class/net/", br_dev)):
        report.die("No such device: %s" % br_dev)

    addrs = addrs_str.split(",")
    if not addrs:
        report.die("At least one address should be used (bridge %s)" % br_dev)

    ips = []
    for addr in addrs:
        if "/" not in addr:
            report.die("No netmask supplied for address %s" % addr)

        ip, mask = addr.split("/")
        try:
            addrpool.parse_address(ip)
        except:
            report.die("Invalid ip address: %s" % ip)

        try:
            int(mask)
        except:
            report.die("Invalid mask: %s" % mask)

        if not (32 >= int(mask) > 0):
            report.die("Mask is out of range: %s" % mask)

        ips.append((ip, mask))

    return br_dev, hwaddr, ips


def must_gen_net(net, count):
    "Generate addresses and hwaddr for network"

    raw_addresses = net["pool"].alloc_addresses(count)
    if raw_addresses is None:
            report.die("Not enough free addresses")

    # FIXME: ip address datatype - string or tuple or smth else?
    raw_mac = (02, random.randint(1, 255)) + addrpool.parse_address(raw_addresses[0])

    mac = ":".join("%x" % digit for digit in raw_mac)
    addresses = [(addr, "24") for addr in raw_addresses] # FIXME: hardcoded netmask!
    return mac, addresses


def free_addresses(used_ranges_path, addresses):
    if not os.path.exists(used_ranges_path):
        return

    f = utils.sync_open(used_ranges_path, "a+")
    pool = addrpool.AddressPool()
    for r in f.read().strip().split():
        pool.add_used_range(r)
    for address in addresses:
        # FIXME: ip/netmasks management should be improved
        pool.free_address(address)
    f.truncate(0)
    f.write("\n".join(pool.dump_used_ranges()))
    f.write("\n") # trailing newline
    f.close()


def update_authorized_keys(key, keypath):

    if not os.path.exists(keypath):
        file = open(keypath, "w")
        if not key.endswith("\n"):
            key += "\n"
        file.write(key)
        file.close()
    else:
        keys = open(keypath, "r").read().strip().split("\n")
        if key not in keys:
            keys.append(key)
            keys.append("")
            tmp_keypath = keypath + ".tmp"
            file = open(tmp_keypath, "w")
            file.write("\n".join(keys))
            file.close()
            os.rename(tmp_keypath, keypath)

def get_balanced_cpu():
    # determine cpu count
    with open("/proc/cpuinfo") as cpuinfo:
        lines = cpuinfo.readlines()
        cpu_count = len(filter(lambda line: line.startswith("processor"), lines))
    # since ubuntu wont run on one cpu (see
    # http://confluence.rn/display/ENV/Fugs ), select two of them
    if cpu_count == 1:
        return "0"

    cpu1 = 2 * random.randint(0, (cpu_count - 1) / 2)
    return "%d,%d" % (cpu1, cpu1+1)

