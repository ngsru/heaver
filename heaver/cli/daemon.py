import os

import heaver.cli.report as report

import heaver.daemon.restapi as restapi
import heaver.daemon.tracker as tracker
import heaver.daemon.ops as ops


def main(args, config):
    t = tracker.Tracker()
    user = config.get("user", "root")
    if "key_path" not in config:
        report.die("'key_path' config option must be set")
    key_path = config["key_path"]
    listen = config.get("listen", "127.0.0.1:8086")
    host, _semicolon, port = listen.partition(":")
    if not port:
        report.die("missing port in listen config item")

    try:
        ops_pool = ops.Pool(user, key_path, t)
    except Exception as e:
        report.die("failed to create operations pool: %s" % e)

    try:
        port = int(port)
        restapi.start(ops_pool, t, host, port)
    except Exception as e:
        report.die("restapi dead: %s" % e)
