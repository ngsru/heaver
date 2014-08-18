import argparse
import logging
import sys
import os
import yaml

import heaver.cli.report as report

try:
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        "Null handler for disabled logging. Backported from 2.7"

        def emit(self, record):
            pass

        def handle(self, record):
            pass

        def createLock(self):
            self.lock = None


def bootstrap():
    parser = argparse.ArgumentParser(description="heaver, the lxc container manager")

    # actions
    parser.add_argument("-S", "--start", action="store_true", help="Start container")
    parser.add_argument("-C", "--create", action="store_true", help="Create container")
    parser.add_argument("-T", "--stop", action="store_true", help="Stop container")
    parser.add_argument("-D", "--destroy", action="store_true", help="Destroy container")
    parser.add_argument("-L", "--list", action="store_true", help="List containers")
    # tarball can haz optional path to tarball
    parser.add_argument("--tarball", nargs="?", const="<generated>",
                        help="Create tarball of container's root")
    parser.add_argument("--send-status", action="store_true", help="Send host status to daemon")
    parser.add_argument("--status", action="store_true", help="Show host status")

    # maintenance actions
    parser.add_argument("--startup", action="store_true",
                        help="Start all containers that should be running")
    parser.add_argument("--shutdown", action="store_true",
                        help="Stop all containers running containers before shutdown")

    # parameters
    parser.add_argument("-n", "--name", help="Name of container")
    parser.add_argument("-k", "--key",
            help="Public ssh key file (will be added to root's authorized keys)")
    parser.add_argument("--raw-key",
            help="Public ssh key as string (will be added to root's authorized keys)")

    root_src = parser.add_mutually_exclusive_group()
    root_src.add_argument("-i", "--image", action="append", help="Image for container")
    root_src.add_argument("-r", "--root", help="Root of container fs")

    parser.add_argument("--net", action="append", help=("Network definition for container."
        " Take name of configured network and, optionally, number of ips from given net"
        " (separated by semicolon), i.e. --net br0 --net br1:2. Distinct virtual interfaces will be"
        " created for each argument"))
    parser.add_argument("--raw-net", action="append", help=("Raw bridged network definition "
        "in form hostbr[/hwaddr]:ip.add.r.ess/mask, i.e. br0:192.168.2.22/24 "
        "br0/02.de.ad.be.ef.01:192.168.2.23/24. hostbr must be set up manually"))

    parser.add_argument("--limit", action="append", help=("Set container limits. Overrides "
        "default values (from config). Format: option=value, available options: cpu, memory"))

    # special modificators
    parser.add_argument("--all", action="store_true",
        help="Operate on all current instances instead of one given")
    parser.add_argument("--force", help="Dont doubt, do what I say")

    # appearance
    parser.add_argument("--format", choices=["pretty", "json"], default="pretty",
        help="Format messages human-readable or machine-readable")
    # parser.add_argument("-v", "--verbose", action="count", help="Set verbosity level")

    # maintenance
    parser.add_argument("--dryrun", action="store_true",
        help="Don't touch anything, report what will be done")
    parser.add_argument("--config", help="Config file to use", default="/etc/heaver/worker.yml")


    args = parser.parse_args()

    if args.format == "pretty":
        report.format = report.format_pretty
        report.die = report.die_pretty
    elif args.format == "json":
        report.format = report.format_json
        report.die = report.die_json

    config = must_read_config(args.config)
    must_set_up_logging(config, args.format)
    must_validate_config(config, args)

    import heaver.cli.main as main
    main.main(args, config)


def bootstrap_imager():
    parser = argparse.ArgumentParser(description="heaver-img, the heaver image operator helper")

    # actions
    parser.add_argument("-S", "--sync", action="store_true", help="Syncronize image(s)")
    parser.add_argument("-C", "--create", action="store_true", help="Create instance of image")
    parser.add_argument("-D", "--destroy", action="store_true", help="Destroy instance(s)")
    parser.add_argument("-A", "--add", action="store_true", help="Add local image to heaver")
    parser.add_argument("-R", "--remove", action="store_true", help="Remove image")

    parser.add_argument("-L", "--list", action="store_true", help="List all instances")

    # parameters
    parser.add_argument("-i", "--image", help="Image id")
    parser.add_argument("-c", "--clone", help="Clone id")
    parser.add_argument("-t", "--tarball", help="Tarballed image for adding")

    # special modificators
    parser.add_argument("--all", action="store_true",
        help="Operate on all current instances instead of one given")
    parser.add_argument("--force", help="Dont doubt, do what I say")

    # appearance
    parser.add_argument("--format", choices=["pretty", "json"], default="pretty",
        help="Format messages human-readable or machine-readable")
    # parser.add_argument("-v", "--verbose", action="count", help="Set verbosity level")

    # maintenance
    parser.add_argument("--dryrun", action="store_true",
        help="Don't touch anything, report what will be done")
    parser.add_argument("--config", help="Config file to use", default="/etc/heaver/worker.yml")


    args = parser.parse_args()

    if args.format == "pretty":
        report.format = report.format_pretty
        report.die = report.die_pretty
    elif args.format == "json":
        report.format = report.format_json
        report.die = report.die_json

    config = must_read_config(args.config)
    must_set_up_logging(config, args.format)

    import heaver.cli.image as image
    image.main(args, config)


def bootstrap_client():
    parser = argparse.ArgumentParser(description="heaverc, the heaver client")

    # actions
    parser.add_argument("-S", "--start", action="store_true", help="Start container")
    parser.add_argument("-C", "--create", action="store_true", help="Create container")
    parser.add_argument("-T", "--stop", action="store_true", help="Stop container")
    parser.add_argument("-D", "--destroy", action="store_true", help="Destroy container")
    parser.add_argument("-L", "--list", action="store_true", help="List containers")
    parser.add_argument("-H", "--list-hosts", action="store_true", help="List hosts")
    parser.add_argument("-I", "--info", action="store_true", help="Show container info")
    parser.add_argument("--tarball", help="Get container's root tarball")
    parser.add_argument("--sync-images", action="store_true",
                        help="Syncronize image given by -i (or all images if none given)")

    # parameters
    parser.add_argument("-n", "--name", help="Name of container")
    parser.add_argument("-i", "--image", action="append", help="Image(s) for container")
    parser.add_argument("--host", help="Host to operate on")
    parser.add_argument("-k", "--key",
            help="Public ssh key (will be added to root's authorized keys)")
    parser.add_argument("--raw-key",
            help="Public ssh key as string (will be added to root's authorized keys)")

    parser.add_argument("--net", action="append", help=("Network definition for container."
        " Take name of configured network and, optionally, number of ips from given net"
        " (separated by semicolon), i.e. --net br0 --net br1:2. Distinct virtual interfaces will be"
        " created for each argument"))

    parser.add_argument("--limit", action="append", help=("Set container limits. Overrides "
        "default values (from config). Format: option=value, available options: cpu, memory"))

    # raw network disabled for client
    #parser.add_argument("--raw-net", action="append", help=("Raw bridged network definition "
    #    "in form hostbr[/hwaddr]:ip.add.r.ess/mask, i.e. br0:192.168.2.22/24 "
    #    "br0/02.de.ad.be.ef.01:192.168.2.23/24. hostbr must be set up manually"))

    # maintenance
    parser.add_argument("--dryrun", action="store_true",
        help="Don't touch anything, report what will be done")
    parser.add_argument("--config", help="Config file to use", default="/etc/heaver/client.yml")

    args = parser.parse_args()

    report.format = report.format_pretty
    report.die = report.die_pretty

    config = must_read_config(args.config)
    must_set_up_logging(config, "pretty")

    import heaver.cli.client as main
    main.main(args, config)


def bootstrap_daemon():
    parser = argparse.ArgumentParser(description="heaverd, the heaver daemon")

    # parameters
    parser.add_argument("--config", help="Config file to use", default="/etc/heaver/daemon.yml")

    args = parser.parse_args()

    report.format = report.format_pretty
    report.die = report.die_pretty

    config = must_read_config(args.config)
    must_set_up_logging(config, "pretty")

    import heaver.cli.daemon as main
    main.main(args, config)

def must_validate_config(config, args):
    "Validate config or die"
    try:
        if args.net and len(args.net):
            networks = [net["name"] for net in config["net"]["networks"]]
            bad_network = set(args.net) - set(networks)
            if len(bad_network):
                raise Exception ("Error network configuration: %s" % ", ".join(list(bad_network)))
        return True
    except Exception as e:
        report.die("Cannot validate config: %s" % e)

def must_read_config(config_file):
    "Load config or die"
    try:
        config = yaml.load(open(config_file))
        return config
    except Exception as e:
        report.die("Cannot load config: %s" % e)


def must_set_up_logging(config, format):
    "Set up logging or die"
    root_logger = logging.getLogger("heaver")
    root_logger.propagate = False

    # set up logging
    if "logging" not in config:
        # logging disabled
        root_logger.addHandler(NullHandler())
    elif not isinstance(config, dict) or not isinstance(config["logging"], dict):
        report.die("Logging config must be dictionary")
    else:
        log_config = config["logging"]

        try:
            log_file = log_config["filename"]
            log_format = log_config["format"]
            if not hasattr(logging, log_config["level"].upper()):
                report.die("Invalid log level for logging: %s" % log_config["level"])
            log_level = getattr(logging, log_config["level"].upper())
        except Exception as e:
            report.die("Malformed logging config: %s" % e)

        try:
            file_stream = open(log_file, "a")
        except Exception:
            report.die("Cannot open log-file '%s' for writing" % log_file)

        file_handler = logging.StreamHandler(file_stream)
        file_handler.setFormatter(logging.Formatter(log_format)) # TODO: check for errors in format?
        file_handler.setLevel(log_level)

        root_logger.addHandler(file_handler)

        if "console_level" in log_config and "console_format" in log_config:
            if not hasattr(logging, log_config["console_level"].upper()):
                report.die("Invalid log level for console logging: %s" %
                    log_config["console_level"])
            log_level = getattr(logging, log_config["console_level"].upper())

            console_handler = logging.StreamHandler(sys.stdout)
            if format == "pretty":
                console_handler.setFormatter(logging.Formatter(log_config["console_format"]))
            elif format == "json":
                console_handler.setFormatter(report.JsonFormatter())

            root_logger.addHandler(console_handler)

