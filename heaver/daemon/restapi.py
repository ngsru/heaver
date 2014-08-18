import flask
import json
import logging
import traceback
import string

import heaver.daemon.pool as pool

app = flask.Flask(__name__)
request = flask.request
ops_pool = None
tracker = None
logger = logging.getLogger("heaver.daemon.restapi")


def start(my_ops_pool, my_tracker, host, port):
    global ops_pool
    ops_pool = my_ops_pool
    global tracker
    tracker = my_tracker

    app.run(host, port, threaded=True)

def root_url(url):
    "Prefix all urls with current api version"
    return "/1" + url

@app.route(root_url("/"), methods=["GET"])
def show_help():
    "Show help for api"
    return "This is helpless help\n" # FIXME: more friendliness

@app.route(root_url("/stats"), methods=["GET"])
def show_stats():
    stats = tracker.get_stats()
    for host in stats.values():
        host["last_seen"] = str(host["last_seen"])
    return json.dumps(stats)


@app.route(root_url("/h/"), methods=["GET"])
def list_hosts():
    hosts = tracker.get_stats()
    for host in hosts.values():
        host["last_seen"] = str(host["last_seen"])
    return json.dumps(hosts)

@app.route(root_url("/h/<host_id>"), methods=["GET"])
def show_host_info(host_id):
    hosts = tracker.get_stats()
    if host_id not in hosts:
        return make_error(404, "no-host-available", "No such host")
    host = hosts[host_id]
    host["last_seen"] = str(host["last_seen"])
    return json.dumps(host)

@app.route(root_url("/h/<host_id>"), methods=["PUT"])
def update_host(host_id):
    update_info = dict()
    form = request.json

    for field in ["roles", "boxes", "la", "fs", "ram", "ips_free", "oom", "now"]:
        if field in form:
            update_info[field] = form[field]
    print "got update for host %s: " % host_id, update_info
    tracker.update_host(host_id, update_info) # TODO: check validity
    return json.dumps(dict(public_key=ops_pool.get_public_key()))

@app.route(root_url("/h/<host_id>"), methods=["POST"])
def handle_host_action(host_id):
    form = request.json
    action = form.get("action")
    images = form.get("args")
    print "action %s, args %s" % (action, images)
    if isinstance(images, basestring):
        images = [images]
    if action == "sync-images":
        executor = ops_pool.get(host_id)
        try:
            return json.dumps(executor.sync_images(images))
        except Exception as e:
            return str(e)
    else:
        return "unknown action"

@app.route(root_url("/h/<host_id>/"), methods=["GET"])
def list_host_boxes(host_id):
    boxes = tracker.get_host(host_id)["boxes"]
    export_boxes = []
    for name, box in boxes.items():
        box["name"] = name
        export_boxes.append(box)
    return json.dumps(export_boxes)

@app.route(root_url("/h/<host_id>/ping"), methods=["GET"])
def ping_host(host_id):
    executor = ops_pool.get(host_id)
    if executor.ping(): #FIXME: correct exit codes?
        return "ok"
    else:
        return "fail"


@app.route(root_url("/c/"), methods=["GET"])
def list_boxes():
    return json.dumps(tracker.get_boxes())

@app.route(root_url("/c/<cont_id>"), methods=["GET"])
def find_box(cont_id):
    box = tracker.find_host_for_box(cont_id)
    if box is None:
        return make_error(404, "no-box-available", "No such box")
    else:
        return flask.redirect(root_url("/h/%s/%s" % (box, cont_id)), code=303)

@app.route(root_url("/c/<cont_id>"), methods=["POST"])
def create_balanced_box(cont_id):
    if request.json is None:
        return make_error(400, "request-is-not-a-json", ("Request must be in json and must "
                                                         "have content type 'application/json'"))
    if "image" not in request.json:
        return make_error(400, "request-missing-image", "'image' field missing in request")
    try:
        image = request.json["image"]
        host = tracker.get_balanced_host()
        executor = ops_pool.get(host)
        cont = executor.create(cont_id, image, request.json)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "No hosts available in pool")
    except:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-create-box", "Worker failed to create box", tb)
    else:
        return concat_json(cont)


@app.route(root_url("/h/<host_id>/<cont_id>"), methods=["GET"])
def show_box_info(host_id, cont_id):
    return json.dumps(tracker.get_box(host_id, cont_id))

@app.route(root_url("/h/<host_id>/<cont_id>"), methods=["PUT"])
def create_box(host_id, cont_id):
    if request.json is None:
        return make_error(400, "request-is-not-a-json", ("Request must be in json and must "
                                                         "have content type 'application/json'"))
    if "image" not in request.json:
        return make_error(400, "request-missing-image", "'image' field missing in request")
    image = request.json["image"]
    try:
        executor = ops_pool.get(host_id)
        cont = executor.create(cont_id, image, request.json)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "No hosts available in pool")
    except:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-create-box", "Worker failed to create box", tb)
    else:
        return concat_json(cont)

@app.route(root_url("/h/<host_id>/<cont_id>"), methods=["POST"])
def update_box(host_id, cont_id):
    # FIXME: parse request and update container
    return ""

@app.route(root_url("/h/<host_id>/<cont_id>"), methods=["DELETE"])
def destroy_box(host_id, cont_id):
    if not tracker.get_box(host_id, cont_id):
        return make_error(404, "no-box-available", "No such box on this host")
    try:
        executor = ops_pool.get(host_id)
        executor.destroy(cont_id)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "Host not found")
    except Exception as e:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-destroy-box", "Worker failed to destroy box", tb)
    return ("", 204, [])


@app.route(root_url("/h/<host_id>/<cont_id>/start"), methods=["POST"])
def start_box(host_id, cont_id):
    if not tracker.get_box(host_id, cont_id):
        return make_error(404, "no-box-available", "No such box on this host")
    try:
        executor = ops_pool.get(host_id)
        executor.start(cont_id)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "Host not found")
    except Exception as e:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-start-box", "Worker failed to start box", tb)
    return ("", 204, [])

@app.route(root_url("/h/<host_id>/<cont_id>/stop"), methods=["POST"])
def stop_box(host_id, cont_id):
    if not tracker.get_box(host_id, cont_id):
        return make_error(404, "no-box-available", "No such box on this host")
    try:
        executor = ops_pool.get(host_id)
        executor.stop(cont_id)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "Host not found")
    except Exception as e:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-stop-box", "Worker failed to stop box", tb)
    return ("", 204, [])

@app.route(root_url("/h/<host_id>/<cont_id>/freeze"), methods=["POST"])
def freeze_box(host_id, cont_id):
    # FIXME: implement in Operator, then there
    return "container %s frozen on %s\n" % (host_id, cont_id)

@app.route(root_url("/h/<host_id>/<cont_id>/unfreeze"), methods=["POST"])
def unfreeze_box(host_id, cont_id):
    # FIXME: implement in Operator, then there
    return "container %s thawed on %s\n" % (host_id, cont_id)

@app.route(root_url("/h/<host_id>/<cont_id>/tarball"), methods=["GET"])
def tarball_box(host_id, cont_id):
    if not tracker.get_box(host_id, cont_id):
        return make_error(404, "no-box-available", "No such box on this host")
    try:
        executor = ops_pool.get(host_id)
        file_gen = executor.make_tarball(cont_id)
    except pool.NoHostAvailable as e:
        return make_error(404, "no-host-available", "Host not found")
    except Exception as e:
        tb = traceback.format_exc()
        return make_error(502, "failed-to-make-tarball", "Worker failed to make tarball", tb)
    return flask.Response(file_gen, mimetype="application/x-tar")

@app.route(root_url("/h/<host_id>/<cont_id>/ping"), methods=["HEAD"])
def ping_box(host_id, cont_id):
    # FIXME: implement in Operator, then there
    return "container %s pinged on %s\n" % (host_id, cont_id)



@app.route("/shutdown_server")
def shutdown_server():
    director.shutdown()
    func = request.environ.get('werkzeug.server.shutdown')
    if func is not None:
        func()
    return ""


def make_error(status_code, message_code, message, debug_info=""):
    errstr = json.dumps(dict(status="error", code=message_code, description=message,
                             info=debug_info))
    return errstr, status_code, [("Content-Type", "application/json")]

def concat_json(input):
    "Concats valid json strings from list `input` into string"
    return "[" + ",".join(map(string.strip, input)) + "]"
