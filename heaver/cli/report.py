import logging
import json
import sys


class JsonFormatter(logging.Formatter):
    "Serialize log record into json"

    def format(self, record):
        data = dict(type="log", level=record.levelname.lower(), message=record.getMessage())
        return json.dumps(data)


def format(rec):
    "Stub"
    return "<stub format>"


def die(rec, exit_code=1):
    "Stub"
    print "<stub die>"
    sys.exit(exit_code)


def format_json(rec):
    "Return given record in json format"
    data = dict(type="result", status=rec["status"], message=rec["message"])
    if "action" in rec:
        data["action"] = rec["action"]
    if "id" in rec:
        data["id"] = rec["id"]
    if "data" in rec:
        data["data"] = rec["data"]
    return json.dumps(data)


def format_pretty(rec):
    "Return given record in pretty, human-readable format"
    return "%(message)s\t%(status)s" % rec


def die_json(rec, exit_code=1):
    "Print error in json and die"
    print json.dumps(dict(type="error", code=exit_code, message=rec))
    sys.exit(exit_code)


def die_pretty(rec, exit_code=1):  # nya, death!
    print rec 
    sys.exit(exit_code)