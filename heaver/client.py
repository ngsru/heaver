import urllib
import httplib
import json
import logging


VERSION = 1
STREAM_CHUNK_SIZE = 64 * 1024


logger = logging.getLogger("heaver.client")

class RequestError(Exception):

    def __init__(self, code, data):
        self.code = code
        self.data = data

    def __str__(self):
        errmsg = []
        errmsg.append("Server Error: status code %d" % self.code)
        if isinstance(self.data, dict):
            errmsg.append("error code: '%s'" % self.data.get("code", "<unknown>"))
            errmsg.append("error desc: %s" % self.data.get("description", "<unknown>"))
            if self.data.get("info"):
                errmsg.append("error debug info: %s" % self.data["info"])
        else:
            errmsg.append("response dump: %s" % str(self.data))
        return "\n".join(errmsg)


class ServerError(RequestError): pass


# simple requests

def request(url, data=None, headers={}, method="GET"):
    if data is None:
        coded_data = ""
    else:
        coded_data = json.dumps(data)

    proto, url = urllib.splittype(url)
    host, path = urllib.splithost(url)
    conn = httplib.HTTPConnection(host)
    conn.request(method, path, coded_data, headers)
    response = conn.getresponse()
    code = response.status

    return code, response, conn

def retrieve(url, data=None, add_headers={}, method="GET"):
    headers = {"Content-type": "application/json"}
    headers.update(add_headers)

    code, response, conn = request(url, data, headers, method)
    answer = response.read()
    logger.debug("request was: '%s', with data: '%s'" % (url, data,))
    logger.debug("response is: '%s'" % (answer,))
    if answer:
        try:
            new_data = json.loads(answer)
        except: # not a json
            new_data = answer
    else:
        new_data = ""
    response.close()
    conn.close()
    if code >= 500:
        raise ServerError(code, new_data)
    if code >= 400:
        raise RequestError(code, new_data)
    return code, new_data

def retrieve_redirect(url, method="HEAD"):
    code, response, conn = request(url, None, dict(), method)
    answer = response.read() # should be empty
    location = response.getheader("Location", "")
    if answer:
        try:
            new_data = json.loads(answer)
        except: # not a json
            new_data = answer
    else:
        new_data = ""
    response.close()
    conn.close()

    if code >= 500:
        raise ServerError(code, new_data)
    if code >= 400:
        raise RequestError(code, new_data)

    return code, location


class Client(object):

    def __init__(self, server):
        self.server = server

    def retrieve(self, url, *args, **kwargs):
        full_url = "http://%s/%d%s" % (self.server, VERSION, url)
        return retrieve(full_url, *args, **kwargs)

    def request(self, url, *args, **kwargs):
        full_url = "http://%s/%d%s" % (self.server, VERSION, url)
        return request(full_url, *args, **kwargs)

    # FIXME: error handling
    # hosts
    def get_stats(self):
        return self.retrieve("/stats")[-1]

    def list_hosts(self):
        return self.retrieve("/h/")[-1]

    def get_host(self, host):
        return self.retrieve("/h/%s" % host)[-1]

    def update_host(self, host, data):
        return self.retrieve("/h/%s" % host, data=data, method="PUT")[-1]

    def sync_images(self, host, images=None):
        data = dict(action="sync-images")
        if images is not None:
            data["args"] = images
        return self.retrieve("/h/%s" % host, data=data, method="POST")[-1]

    def ping_host(self, host):
        pass

    # containers
    def list_containers(self, host=None):
        if host is not None:
            url = "/h/%s/" % host
        else:
            url = "/c/"
        return self.retrieve(url, method="GET")[-1]

    def get_container(self, box, host=None):
        if host is None:
            container_url = self.find_container(box)
        else:
            container_url = "/h/%s/%s" % (host, box)

        return self.retrieve(container_url, method="GET")

    def find_container(self, box):
        code, location = retrieve_redirect("http://%s/%d/c/%s" % (self.server, VERSION, box))
        if code not in (303,):
            raise_bad_response(code, "")

        uri = self.extract_uri(location)
        if uri is None:
            raise RequestError(code, "Invalid location in redirect")
        return uri

    def create_container(self, box, image, host=None, options=dict()):
        if host:
            url = "/h/%s/%s" % (host, box)
        else:
            url = "/c/%s" % box # server will balance container creation

        all_options = dict(image=image)
        all_options.update(options)
        response = self.retrieve(url, data=all_options, method="POST")
        return response[-1][-1]

    def destroy_container(self, box, host=None):
        if host is None:
            container_url = self.find_container(box)
        else:
            container_url = "/h/%s/%s" % (host, box)

        return self.retrieve(container_url, method="DELETE")

    def update_container(self, box, opts):
        pass

    # container actions
    def start_container(self, box, host=None):
        if host is None:
            container_url = self.find_container(box)
        else:
            container_url = "/h/%s/%s" % (host, box)
        url = "%s/start" % container_url
        return self.retrieve(url, method="POST")

    def stop_container(self, box, host=None):
        if host is None:
            container_url = self.find_container(box)
        else:
            container_url = "/h/%s/%s" % (host, box)
        url = "%s/stop" % container_url
        return self.retrieve(url, method="POST")

    def freeze_container(self, box):
        pass

    def unfreeze_container(self, box):
        pass

    def make_tarball(self, box, tar_file, host=None):
        if host is None:
            container_url = self.find_container(box)
        else:
            container_url = "/h/%s/%s" % (host, box)
        url = "%s/tarball" % container_url

        code, response, conn = self.request(url, None, dict(), "GET")
        if code >= 400:
            data = response.read()
            response.close()
            conn.close()

            if code >= 500:
                raise ServerError(code, data)
            if code >= 400:
                raise RequestError(code, data)

        # copy stream to fd
        try:
            while True:
                chunk = response.read(STREAM_CHUNK_SIZE)
                if chunk == "":
                    break
                tar_file.write(chunk)
        finally:
            response.close()
            conn.close()

        return code, None


    # util
    def extract_uri(self, url):
        "Extract api uri from full url"
        prefix = "http://%s/%d" % (self.server, VERSION)
        if url.find(prefix) == 0:
            return url[len(prefix):]
        else:
            return None
