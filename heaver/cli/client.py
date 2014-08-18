import os

import heaver.cli.report as report
import heaver.client as client


def main(args, config):

    actions = [args.start, args.stop, args.create, args.destroy, args.list, args.list_hosts,
               args.info, args.tarball, args.sync_images]

    if not any(actions):
        report.die("No action given")

    if args.start and args.stop: #TODO: can act as restart
        report.die("Cannot start and stop container simultaneously (-ST given)")

    if args.create and args.destroy:
        report.die("Cannot create and destroy container simultaneously (-CD given)")

    if "server" not in config:
        report.die("No 'server' in config")

    if not isinstance(config["server"], basestring):
        report.die("'server' parameter must be string")

    c = client.Client(config["server"])
    if args.create:
        create(args, config, c)

    if args.start:
        start(args, config, c)

    if args.stop:
        stop(args, config, c)

    if args.destroy:
        destroy(args, config, c)

    if args.list:
        list_containers(args, config, c)

    if args.list_hosts:
        list_hosts(args, config, c)

    if args.info:
        show_info(args, config, c)

    if args.tarball:
        make_tarball(args, config, c)

    if args.sync_images:
        sync_images(args, config, c)

def create(args, config, c):
    if not args.image:
        report.die("Cannot create container without image (supply -i with image id)")

    if not args.name:
        report.die("Cannot create container without name (supply -n with name)")

    if args.host:
        host = args.host
    else:
        host = None

    key = None
    if args.key:
        try:
            with open(args.key) as key_file:
                key = key_file.read()
        except Exception as e:
            report.die("Cannot read given key file: %s" % e)
    elif args.raw_key:
        key = args.raw_key

    net = args.net or []
    options = dict(net=net)
    if key is not None:
        options["key"] = key
    if args.limit is not None and len(args.limit) > 0:
        options["limit"] = args.limit
    try:
        container = c.create_container(args.name, args.image, host, options)
    except client.RequestError as e:
        print "Failed to create container!"
        print e
    else:
        print container


def start(args, config, c):
    if not args.name:
        report.die("Cannot start container without name (supply -n with name)")

    try:
        result = c.start_container(args.name, args.host)
    except client.RequestError as e:
        print "Failed to start container!"
        print e
    else:
        print result


def stop(args, config, c):
    if not args.name:
        report.die("Cannot stop container without name (supply -n with name)")

    try:
        result = c.stop_container(args.name, args.host)
    except client.RequestError as e:
        print "Failed to stop container!"
        print e
    else:
        print result


def destroy(args, config, c):
    if not args.name:
        report.die("Cannot destroy container without name (supply -n with name)")

    try:
        result = c.destroy_container(args.name, args.host)
    except client.RequestError as e:
        print "Failed to destroy container!"
        print e
    else:
        print result


def list_containers(args, config, c):
    # FIXME: error handling
    result = c.list_containers(args.host)
    print "\n".join(format_containers(result))


def list_hosts(args, config, c):
    # FIXME: error handling
    if args.host:
        info = c.get_host(args.host)
        result = {args.host: info}
    else:
        result = c.list_hosts()
    print format_hosts(result)


def show_info(args, config, c):
    if not args.name:
        report.die("Cannot stat container without name (supply -n with name)")

    # FIXME: error handling
    result = c.get_container(args.name)
    print result


def make_tarball(args, config, c):
    if not args.name:
        report.die("Specify container to make tarball from (supply -n with name)")

    tar_path = args.tarball
    try:
        tar_file = open(tar_path, "wb")
    except Exception as e:
        report.die("Cannot open file '%s' for writing: %s" % (tar_path, e))

    try:
        result = c.make_tarball(args.name, tar_file)
    except Exception as e:
        os.unlink(tar_path)
        report.die("Cannot write tarball: %s" % e)
    finally:
        tar_file.close()

    print "tarball saved on: %s" % tar_path


def sync_images(args, config, c):
    hosts = []
    if args.host:
        hosts = [args.host]
    else:
        hosts = c.list_hosts()

    if args.image:
        image = args.image
    else:
        image = None

    for host in hosts:
        print c.sync_images(host, image)


def format_hosts(hosts):
    formatted_hosts = dict()
    for hostname, host in hosts.items():
        lines = [hostname]
        lines.append("-" * len(hostname))

        table = []
        hwinfo = "%d cores, %d Gb memory" % (host["la"]["cpus"], host["ram"]["total"] / 1024 / 1024)
        table.append(("hw", hwinfo))

        total_ram = host["ram"]["total"]
        loadinfo = "%d processes running, %d loadavg15, mem used hard/soft: %d/%d Mb (%d/%d %%)" % \
                (host["la"]["running"], host["la"]["avg15"],
                 host["ram"]["hard_used"] / 1024, host["ram"]["soft_used"] / 1024,
                 host["ram"]["hard_used"] * 100 / total_ram,
                 host["ram"]["soft_used"] * 100 / total_ram)
        table.append(("load", loadinfo))

        alive = "alive" if host["alive"] else "dead"
        stale = "(stale)" if host["stale"] else ""
        okinfo = "%s, last seen at %s %s" % (alive, host["last_seen"], stale)
        table.append(("status", okinfo))

        boxlist = []
        for boxname, box in host["boxes"].items():
            active = "active" if box["active"] else "inactive"
            ips = ", ".join(sum(box["ips"].values(), []))
            boxinfo = "%s, %s" % (active, ips)
            boxlist.append((boxname, boxinfo))
        table.append(("boxes", boxlist))

        lines.extend(format_table(table))
        formatted_hosts[hostname] = lines

    sorted_names = sorted(formatted_hosts.keys())
    all_hosts = []
    for name in sorted_names:
         all_hosts.append("\n".join(formatted_hosts[name]))

    return "\n\n".join(all_hosts)

def format_table(table):
    if len(table) == 0:
        return []
    max_length = max(map(lambda row: len(row[0]), table))
    lines = []
    for name, data in table:
        if isinstance(data, basestring):
            lines.append("%s: %s" % (name.rjust(max_length, " "), data))
        elif isinstance(data, list):
            if len(data) == 0:
                continue
            lines.append("%s:" % (name.rjust(max_length, " ")))
            max_item_length = max(map(lambda row: len(row[0]), data))
            for iname, idata in data:
                lines.append("%s: %s" % (iname.rjust(max_length + max_item_length), idata))
    return lines

def format_containers(containers):
    if len(containers) == 0:
        return []

    def format(container):
        container["active"] = "active" if container["active"] else "inactive"
        container["ips"] = ", ".join(sum(container["ips"].values(), []))
        data_template = "%(active)s, %(ips)s"
        if "running_on" in container:
            name_template = "%(name)s (on %(running_on)s): "
        else:
            name_template = "%(name)s: "
        return (name_template % container, data_template % container)

    rows = map(format, containers)
    max_length = max(map(lambda (name, data): len(name), rows))

    def ident_glue(row):
        return row[0].rjust(max_length) + row[1]

    return map(ident_glue, rows)

