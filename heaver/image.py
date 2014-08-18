import os
import shutil
import logging
import datetime
import hashlib
import urllib2
import json
import glob
import fcntl
from subprocess import Popen, PIPE


logger = logging.getLogger("heaver.image")

def exec_(cmd):
    proc = Popen(cmd, stdout=PIPE, env=os.environ)
    out = proc.communicate()
    if proc.returncode != 0:
        raise Exception("Error during executing {0}."
            "\nstd_out:\n{1}\nstd_err:\n{2}".format(" ".join(cmd),out[0],out[1]))
    return out[0]

def get_hash(path):
    """Returns sha1 hash of given file"""
    logger.debug("Calculating hash for {0}".format(path))
    hsh = hashlib.sha1()
    with open(path,"rb") as f:
        while True:
            buf = f.read(4096)
            if not buf: break
            hsh.update(buf)
    return hsh.hexdigest()

def lock(file):
    "Lock @file"
    fcntl.flock(file, fcntl.LOCK_EX)

def unlock(file):
    "Release @file"
    fcntl.flock(file, fcntl.LOCK_UN)


class RemoteError(Exception): pass

class ImageOperator(object):

    def __init__(self, config):
        self._config = config

    def create_instance(self, id, name=None):
        "Creates rootfs to be used by lxc, from, specified by id, image"
        pass

    def destroy_instance(self, path):
        "Removes specified root"
        pass

    def assemble_instance(self, path):
        "Prepares root for container (pre-start hook)"
        pass

    def disassemble_instance(self, path):
        "Cleanups root of container (post-shutdown hook)"
        pass

    def list_instances(self):
        "Returns list of all instances on the node"
        if not os.path.exists(self._config["path_to_instances_dir"]):
            return []
        return os.listdir(self._config["path_to_instances_dir"])

    def list_images(self):
        "Returns list of all images on the node"
        if not os.path.exists(self._config["path_to_images_dir"]):
            return []
        return os.listdir(self._config["path_to_images_dir"])

    def add_image(self, path, id):
        pass

    def delete_image(self, id):
        pass

    def get_free_space(self):
        pass

    def get_image_hash(self, id):
        "Returns hash of image or None if not found"
        path = os.path.join(self._config["path_to_images_dir"], id, "hash")
        if not os.path.exists(path):
            return None
        with open(path) as hash_file:
            return hash_file.read().strip()

    def sync_images(self, images=[]):
        "Syncronize outdated images with server"
        result = []
        if not self._config.get("remote_image_url"):
            logger.info("No remote image server available, skipping sync")
            return []
        # download remote listing
        try:
            images_in_repo = self._get_repo_images()
        except Exception as e:
            logger.error("Cannot retrieve image listing from server: '%s'" % e)
            raise RemoteError(e)
        owned_images = self.list_images()
        for image in images:
            if image not in images_in_repo:
                if image not in owned_images:
                    logger.error("Image '%s' does not exist on server" % image)
                    result.append((image, "error"))
                else:
                    logger.info("Image '%s' is local" % image)
                    result.append((image, "local"))
                continue

            # acquire syncronization lock
            lock_path = os.path.join(self._config["path_to_locks_dir"], image + ".sync.lock")
            lock_file = open(lock_path, "w")
            logger.info("acquiring SYNC lock for image '%s'" % image)
            lock(lock_file)

            image_hash = self.get_image_hash(image)
            if image_hash is None:
                logger.warning("Hashsum missing for image '%s'" % image)
                updated = self.update_image(image)
                result.append((image, updated))
            else:
                if image_hash != images_in_repo[image]["hashsum"]:
                    logger.info("Image '%s' has updates, retrieving them" % image)
                    updated = self.update_image(image)
                    result.append((image, updated))
                else:
                    logger.info("Image '%s' is up to date" % image)
                    result.append((image, "in-sync"))

            logger.info("releasing SYNC lock for image '%s'" % image)
            unlock(lock_file)
            lock_file.close()

        return result

    def update_image(self, image):
        "Update image from server"
        logger.info("updating image " + image)
        try:
            downloaded_image, hash = self.download_image(image)
        except Exception as e:
            logger.error("Failed to download updated image '%s': '%s'" % (image, e))
            return "error"
        if image in self.list_images():
            try:
                self.delete_image(image)
            except Exception as e:
                logger.error("Failed to truncate image '%s' on update: '%s'" % (image, e))
                os.unlink(downloaded_image)
                return "error"
        try:
            self.add_image(downloaded_image, image)
        except Exception as e:
            logger.error("Failed to add updated image '%s': '%s'" % (image, e))
            return "error"
        finally:
            os.unlink(downloaded_image)
        return "updated"

    def download_image(self, id):
        logger.info("downloading image {0} (this may take a while)".format(id))
        download_url = os.path.join(self._config["remote_image_url"], id)
        image_path = "/var/lib/heaver/tmp/%s.tar" % id
        if not os.path.exists("/var/lib/heaver/tmp"):
            os.mkdir("/var/lib/heaver/tmp")

        hash = hashlib.sha1()
        remote_image = urllib2.urlopen(download_url)
        full_url = remote_image.geturl()
        origin_hash = extract_hashsum(full_url)
        if origin_hash is None:
            remote_image.close()
            raise Exception("Server returned url without proper hash")

        with open(image_path,'wb') as local_image:
            try:
                while True:
                    buf = remote_image.read(4096)
                    if not buf: break
                    local_image.write(buf)
                    hash.update(buf)
            finally:
                remote_image.close()
                local_image.close()

        dl_hash = hash.hexdigest()
        if dl_hash != origin_hash:
            logger.error("Hashsum mismatch for downloaded image '%s'" % id)
            os.unlink(image_path)
            raise Exception("Hashsum mismatch")
        logger.info("Donwloaded image {0} to {1}".format(id,image_path))
        return image_path, dl_hash

    def _get_repo_images(self):
        "Retrieve image list with hashes from server"
        req = urllib2.Request(self._config["remote_image_url"],
                headers=dict(Accept="application/json"))
        answer = urllib2.urlopen(req)
        raw_images = json.load(answer)
        images = dict()
        for raw_image in raw_images:
            images[raw_image["name"]] = raw_image
        return images

    def _get_instanse_id(self):
        return datetime.datetime.now().isoformat().replace(':','').replace('.','')

    def _mount(self, dev, path):
        "Mount dev to the path"
        exec_(["mount", dev, path])

    def _umount(self, path):
        "Unmount path"
        exec_(["umount", path])

    def _untar(self, tar, path):
        "Extract tar to path"
        exec_(["tar", "xf", tar, "-C", path])


class ZfsImageOperator(ImageOperator):

    def _mount(self, zfs_path, path):
        "Mount dev to the path"
        logger.debug("Mounting {0} to {1}".format(zfs_path, path))
        self._set_zfs_property(zfs_path, 'mountpoint', path)
        if self._list_mounts().get(zfs_path) is None:
            exec_(["zfs", "mount", zfs_path])

    def _list_mounts(self):
        "Retrieve mounted fs's"
        mount_lines = exec_(["zfs", "mount"]).splitlines()
        mounts = dict()
        for line in mount_lines:
            fs, mountpoint = line.split(" ", 1)
            mounts[fs] = mountpoint.strip()
        return mounts

    def _umount(self, path):
        "Unmount path"
        mounts = self._list_zfs_fs()
        mounts = filter(lambda x: x["mountpoint"] == path, mounts)
        if len(mounts) == 1:
            logger.debug("Unmounting {0}".format(path))
            exec_(["zfs", "unmount", mounts[0]["name"]])

    def _get_zfs_property(self, zfs_path, prop):
        "Returns value of @prop for @zfs_path"
        logger.debug("Getting {0} property of {1}".format(prop, zfs_path))
        try:
            res = exec_(["zfs","get", prop, zfs_path]).splitlines()[1]
        except Exception as e:
            logger.critical("Error during getting zfs property {0} for {1}"
                "\n======\n{2}\n".format(prop,zfs_path,e))
            raise
        res = res.split()[2]
        return res

    def _set_zfs_property(self, zfs_path, prop, value):
        "Set @prop=@value for @zfs_path"
        logger.debug("Setting {0} property of {1} value {2}".format(prop, zfs_path, value))
        try:
            exec_(["zfs","set", "{0}={1}".format(prop,value), zfs_path])
        except Exception as e:
            logger.critical("Error during setting zfs property {0}={1} for {2}"
                "\n======\n{3}\n".format(prop,value,zfs_path,e))
            raise

    def _create_zfs_fs(self, zfs_path, size):
        "Create zfs fs with path @zfs_path with size @size"
        logger.debug("Creating zfs fs {0} with size {1}".format(zfs_path, size))
        created = False
        try:
            exec_(["zfs","create",zfs_path])
            created = True
            self._set_zfs_property(zfs_path, 'reservation', size)
        except Exception as e:
            logger.critical("Error during creating fs {0}\n======\n{1}".format(zfs_path,e))
            if created: self._destroy_zfs_fs(zfs_path)
            raise
        finally:
            logger.debug("Created")

    def _create_zfs_snapshot(self, zfs_origin_path, snapshot_name):
        "Create zfs snapshot with given name"
        name = zfs_origin_path + "@" + snapshot_name
        logger.debug("Creating snapshot {0}".format(name))

        try:
            exec_(["zfs", "snapshot", name])
        except Exception as e:
            logger.critical("Error during creating snapshot {0}"
                "\n======\n{1}".format(name))
            raise
        finally:
            logger.debug("Created")
        return name

    def _create_zfs_clone(self, zfs_snapshot, zfs_clone_path):
        "Create clone of zfs snapshot with given zfs path"
        parent = zfs_snapshot.split('@')[0]
        reserv = self._get_zfs_property(parent, 'reservation')
        logger.debug("Creating clone of {0}".format(zfs_snapshot))
        created = False
        try:
            exec_(["zfs", "clone", zfs_snapshot, zfs_clone_path])
            created = True
            self._set_zfs_property(zfs_clone_path, 'reservation', reserv)
        except Exception as e:
            logger.critical("Error during creating clone of {0}\n{1}".format(zfs_snapshot, e))
            if created: self._destroy_zfs_fs(zfs_clone_path)
            raise
        finally:
            logger.debug("Created")

    def _destroy_zfs_fs(self, zfs_path):
        "Destroy zfs instance (fs, clone, snapshot)"
        logger.debug("Destroying {0}".format(zfs_path))
        try:
            exec_(["zfs","destroy",zfs_path])
        except Exception as e:
            logger.critical("Error during destroying {0}\n{1}".format(zfs_path,e))
            raise
        finally:
            logger.debug("Destroyed")

    def _list_zfs_fs(self, origin=None):
        "Returns list of zfs file systems for given parent, or all file systems if no origin given"
        if origin and '@' in origin:
            ff = lambda x: origin == x["origin"]
        else:
            ff = lambda x: origin == x["origin"].split('@')[0]
        try:
            raw_items = exec_(["zfs", "list", "-H", "-o", "origin,name,mountpoint"]).splitlines()
        except Exception, e:
            logger.critical("Error during listing zfs fs\n{0}".format(e))
            raise

        items = map(lambda row: dict(zip(["origin", "name", "mountpoint"], row.split("\t"))),
                        raw_items)

        if origin:
            return filter(ff, items)
        return items

    def _list_zfs_snapshots(self, origin=None):
        "Returns list of zfs snapshots of given fs, or all if not given"
        if origin and '@' in origin:
            ff = lambda x: origin == x
        else:
            ff = lambda x: origin == x.split('@')[0]

        try:
            items = exec_(["zfs", "list", "-H", "-t", "snapshot", "-o", "name"]).splitlines()
        except Exception, e:
            logger.critical("Error during listing zfs snapshots\n{0}".format(e))
            raise

        if origin:
            return filter(ff, items)
        return items

    def _ensure_mounted(self, id):
        "Ensures that dataset is mounted"
        all_fs = self._list_zfs_fs()
        zfs_name = "%s/%s" % (self._config["zfs_pool"], id)
        for fs in all_fs:
            if fs["name"] == zfs_name:
                mountpoint = fs["mountpoint"]
                if not os.path.ismount(mountpoint):
                    self._mount(zfs_name, mountpoint)

    def _check_zfs_existance(self, zfs_path):
        if zfs_path in map(lambda x: x["name"],
            self._list_zfs_fs()) or zfs_path in self._list_zfs_snapshots():
            return True
        return False

    def _get_base_snapshot(self, origin):
        "Return latest snapshot"
        zfs_path = self._config["zfs_pool"] + "/" + origin
        current_snaps = self._list_zfs_snapshots(zfs_path)
        # remove snapshot-flag named 'active'
        current_snaps = filter(lambda snap: not snap.endswith("@active"), current_snaps)
        if len(current_snaps) == 0:
            # don't have snapshots yet, create one
            now = datetime.datetime.now().isoformat().replace(':','').replace('.','')
            return self._create_zfs_snapshot(zfs_path, now)
        else:
            return sorted(current_snaps)[-1]


    def create_instance(self, id, name=None):
        "Create zfs clone of image with provided id"
        if not id in self.list_images():
            raise Exception("No such image: '%s'" % id)

        lock_path = os.path.join(self._config["path_to_locks_dir"], id + ".op.lock")
        lock_file = open(lock_path, "w")
        logger.info("acquiring OP lock for image '%s'" % id)
        lock(lock_file)

        image_zfs_path      = os.path.join(self._config['zfs_pool'], id)
        base_snapshot       = self._get_base_snapshot(id)
        clone_name          = id + "." + self._get_instanse_id()
        clone_zfs_path      = os.path.join(self._config['zfs_pool'], clone_name)

        if name is not None:
            clone_name = name + "@" + clone_name

        instance_mount_path = os.path.join(self._config["path_to_instances_dir"], clone_name)

        # Rollback flags
        clne    = False
        dir     = False

        # Creating instance
        if not os.path.exists(self._config["path_to_instances_dir"]):
            logger.debug("No instance folder, creating")
            os.makedirs(self._config["path_to_instances_dir"])

        logger.info("Creating instance {0} from image {1}".format(clone_name, id))
        try:
            logger.debug("Creating clone {0}".format(clone_zfs_path))
            self._create_zfs_clone(base_snapshot, clone_zfs_path)
            clne = True
            logger.debug("Creating mount point {0}".format(instance_mount_path))
            os.mkdir(instance_mount_path)
            dir = True
            logger.debug("Mounting created clone")
            self._mount(clone_zfs_path, instance_mount_path)
        except Exception, e:
            logger.critical("Error during creating instance. Rolling back")
            if dir:
                logger.critical("Removing mountpoint {0}".format(instance_mount_path))
                os.rmdir(instance_mount_path)
            if clne:
                logger.critical("Destroying clone")
                self._destroy_zfs_fs(clone_zfs_path)
            raise
        logger.info("Instance {0} created".format(clone_name))

        logger.info("releasing OP lock for image '%s'" % id)
        unlock(lock_file)
        lock_file.close()

        return instance_mount_path


    def assemble_instance(self, path):
        if (os.path.abspath(os.path.dirname(path)) !=
                os.path.abspath(self._config["path_to_instances_dir"])):
            raise ValueError("Given path does not belong to heaver")
        instance_id = os.path.basename(path)
        logger.debug("Assembling '{0}' instance".format(instance_id))

        err     = False
        opstats = ""
        excepts = []

        if not instance_id in self.list_instances():
            logger.info("No instance with id {0}".format(id))
            return

        try:
            mount = self._list_zfs_fs()
        except Exception, e:
            err = True
            excepts.append(e)

        zfs_path = None
        # Getting info about parent of removing instance
        for mnt in mount:
            if mnt["mountpoint"] == path:
                zfs_path = mnt["name"]
                break

        if not zfs_path:
            logger.info("No instance with path {0} found. Nothing to do.".format(path))
            return

        if not os.path.ismount(path):
            self._mount(zfs_path, path)


    def disassemble_instance(self, path):
        if (os.path.abspath(os.path.dirname(path)) !=
                os.path.abspath(self._config["path_to_instances_dir"])):
            raise ValueError("Given path does not belong to heaver: '{0}'".format(path))
        instance_id = os.path.basename(path)
        logger.debug("Disassembling '{0}' instance".format(instance_id))

        if not instance_id in self.list_instances():
            logger.info("No instance with id {0}".format(id))
            return

        if os.path.ismount(path):
            self._umount(path)

    def _collect_garbage(self, image):
        "Remove unused snapshots of image and, if no children left, image itself"
        origin = "%s/%s" % (self._config["zfs_pool"], image)
        snapshots = self._list_zfs_snapshots(origin)
        if len(snapshots) == 0:
            self.delete_image(origin)

        for snap in snapshots:
            if snap.endswith("@active"):
                continue
            try:
                clones = self._get_zfs_property(snap, "clones")
            except:
                pass
            else:
                if clones == "-":
                    self._destroy_zfs_fs(snap)


    def destroy_instance(self, path):
        "Unmount zfs cloned instance. And destroy it."
        if (os.path.abspath(os.path.dirname(path)) !=
                os.path.abspath(self._config["path_to_instances_dir"])):
            raise ValueError("Given path does not belong to heaver")
        instance_id = os.path.basename(path)
        logger.debug("Destroying '{0}' instance".format(instance_id))

        err     = False
        opstats = ""
        excepts = []

        if not instance_id in self.list_instances():
            logger.info("No instance with id {0}".format(id))
            return

        try:
            mount = self._list_zfs_fs()
        except Exception, e:
            err = True
            excepts.append(e)

        zfs_path = None
        # Getting info about parent of removing instance
        for mnt in mount:
            if mnt["mountpoint"] == path:
                zfs_origin = mnt["origin"]
                zfs_path = mnt["name"]
                break

        if not zfs_path:
            logger.info("No instance with path {0} found. Remove instance dir.".format(path))
            os.rmdir(path)
            return

        zfs_origin_fs = zfs_origin.split('@')[0]

        if os.path.ismount(path):
            try:
                self._umount(path)
                opstats += "Unmounted: OK\n"
            except Exception, e:
                err = True
                opstats += "Unmounted: Err\n"
                excepts.append(e)

        # lock operations with origin fs
        image = os.path.basename(zfs_origin_fs)
        lock_path = os.path.join(self._config["path_to_locks_dir"], image + ".op.lock")
        lock_file = open(lock_path, "w")
        logger.info("acquiring OP lock for image '%s'" % image)
        lock(lock_file)

        try:
            self._destroy_zfs_fs(zfs_path)
            opstats += "Destroyed instance: OK\n"
        except Exception, e:
            err = True
            opstats += "Destroyed instance: Err\n"
            excepts.append(e)

        try:
            os.rmdir(path)
            hold_file = path + ".hold"
            if os.path.exists(hold_file):
                os.unlink(hold_file)
            opstats += "Dir removed: OK\n"
        except Exception, e:
            err = True
            opstats += "Dir return: Err\n"
            excepts.append(e)

        # Counting number of children of snapshot
        # drop snapshot if no clones left
        # but keep if it is the 'actual' snapshot and image is active
        children = len(self._list_zfs_fs(zfs_origin))
        if children == 0:
            if not (self._check_zfs_existance(zfs_origin_fs + "@active") and
                    self._get_base_snapshot(zfs_origin_fs.split("/", 1)[-1]) == zfs_origin):

                try:
                    self._destroy_zfs_fs(zfs_origin)
                    opstats += "Destroying snapshot: OK\n"
                except Exception, e:
                    err = True
                    opstats += "Destroying snapshot: Err\n"
                    excepts.append(e)


        # Get list of all snapshots on image fs
        # drop image if no snapshots left
        # note: active images must have at least @active snapshot
        try:
            zfs_snapshots = self._list_zfs_snapshots(zfs_origin_fs)
        except Exception, e:
            err = True
            excepts.append(e)

        if len(zfs_snapshots) == 0:
            try:
                opstats += "Destroyed image fs: OK"
                self._destroy_zfs_fs(zfs_origin_fs)
            except Exception, e:
                err = True
                opstats += "Destroyed image fs: Err"
                excepts.append(e)

        logger.info("releasing OP lock for image '%s'" % image)
        unlock(lock_file)
        lock_file.close()

        if err:
            raise Exception("Error during destroying instance. {0}".format("\n".join(map(str, excepts))))

    def sync_images(self, images=[]):
        # mount all images we have
        all_images = self.list_images()
        for image in all_images:
            self._ensure_mounted(image)

        return super(ZfsImageOperator, self).sync_images(images)

    def add_image(self, path_to_tar, id, size=None):
        "Create new zfs volume and make snapshot"

        lock_path = os.path.join(self._config["path_to_locks_dir"], id + ".op.lock")
        lock_file = open(lock_path, "w")
        logger.info("acquiring OP lock for image '%s'" % id)
        lock(lock_file)

        path_to_img = os.path.join(self._config["path_to_images_dir"], id)
        path_to_img_hash = os.path.join(path_to_img, "hash")
        zfs_path = os.path.join(self._config['zfs_pool'], id)
        hash = get_hash(path_to_tar)
        if not os.path.exists(self._config["path_to_images_dir"]):
            logger.debug("No image folder, creating")
            os.makedirs(self._config["path_to_images_dir"])
        # Check if images dir exists and create if missing
        if id in self.list_images():
            logger.info("Image {0} already exists. NothinToDo.".format(id))
            if os.path.exists(path_to_img_hash):
                with open(path_to_img + "/hash","r") as f:
                    old_hash = f.read()
                if old_hash == hash:
                    logger.info("Image that you try to add already exists, and it's identical")
                    return
                else:
                    logger.critical("Image with id {0} already exists".format(id))
                    raise Exception("Image with id {0} already exists".format(id))
            else:
                logger.critical("Image with id {0} already exists".format(id))
                raise Exception("Image with id {0} already exists".format(id))

        if self._check_zfs_existance(zfs_path) and self._check_zfs_existance(zfs_path + "@active"):
            logger.info(("Image {0} still not totally deleted. "
                    "Please use other name, or delete all children:\n{1}").format(
                id, map(lambda x: x["name"], self._list_zfs_fs(zfs_path))))
            raise Exception("Image with id {0} already exists".format(id))

        mounted = False
        snapshot_created = False
        base_snapshot_created = False
        fs_created = False
        dir_created = False
        try:
            os.mkdir(path_to_img)
            dir_created = True
            if not size:
                size = self._config["zfs_fs_size"]
            # there is may be zfs fs for previous incarnation of image
            # we can reuse it, because it must be empty
            if self._check_zfs_existance(zfs_path):
                self._set_zfs_property(zfs_path, "canmount", "on")
                self._mount(zfs_path, path_to_img)
            else:
                self._create_zfs_fs(zfs_path, size)
                fs_created = True
            self._create_zfs_snapshot(zfs_path, 'active')
            snapshot_created = True
            self._mount(zfs_path, path_to_img)
            mounted = True
            self._untar(path_to_tar, path_to_img)
            try:
                with open(path_to_img_hash, "w") as f:
                    f.write(hash)
                    f.close()
            except Exception, e:
                logger.error("Error during calculating hash\n======\n{0}".format(e))
            base_snapshot = datetime.datetime.now().isoformat().replace(':','').replace('.','')
            self._create_zfs_snapshot(zfs_path, base_snapshot)
            base_snapshot_created = True
        except Exception as e:
            if base_snapshot_created:
                self._destroy_zfs_fs(zfs_path + "@" + base_snapshot)
            if mounted:
                self._umount(path_to_img)
            if snapshot_created:
                self._destroy_zfs_fs(zfs_path+"@active")
            if fs_created:
                self._destroy_zfs_fs(zfs_path)
            if dir_created:
                os.rmdir(path_to_img)
            logger.critical("Error during adding image with id {0}. Rolling back"
                "\n======\n{1}".format(id, str(e)))

        logger.info("releasing OP lock for image '%s'" % id)
        unlock(lock_file)
        lock_file.close()

    def delete_image(self, id):
        "Remove image by id"

        lock_path = os.path.join(self._config["path_to_locks_dir"], id + ".op.lock")
        lock_file = open(lock_path, "w")
        logger.info("acquiring OP lock for image '%s'" % id)
        lock(lock_file)

        opstats = ""
        excepts = []
        err     = False
        if not id in self.list_images():
            logger.info("No such image.")
            return
        path_to_img = os.path.join(self._config["path_to_images_dir"], id)
        zfs_path = "%s/%s" % (self._config['zfs_pool'], id)
        zfs_active_snapshot = zfs_path + "@active"
        if not self._check_zfs_existance(zfs_path):
            logger.info("No such zfs fs {0}. Deleting image dir {1}.".format(zfs_path, path_to_img))
            try:
                os.rmdir(path_to_img)
            except Exception, e:
                logger.critical("Error during deleting image dir {0}.")
                raise
            return

        # Counting number of children of image fs
        try:
            # remove unused snapshots
            self._collect_garbage(id)
        except Exception, e:
            err = True
            excepts.append(e)
        # Marking as not active
        if self._check_zfs_existance(zfs_path):
            try:
                self._destroy_zfs_fs(zfs_active_snapshot)
                opstats += "Destroyed @active snapshot: OK\n"
            except Exception, e:
                err = True
                opstats += "Destroyed @active snapshot: Err\n"
                excepts.append(e)
        children = len(self._list_zfs_fs(zfs_path))
        if children == 0: # If no children then remove
            try:
                opstats += "Destroyed fs: OK\n"
                self._destroy_zfs_fs(zfs_path)
            except Exception, e:
                opstats += "Destroyed fs: Err\n"
                err = True
                excepts.append(e)
        else:
            # image will be removed when all children are destroyed
            # now remove it content and mountpoint

            self.truncate_image(id)
            self._set_zfs_property(zfs_path, "canmount", "off")
        try:
            os.rmdir(path_to_img)
            opstats += "Dir removed: OK\n"
        except Exception, e:
            err = True
            opstats += "Dir removed: Err\n"
            excepts.append(e)

        logger.info("releasing OP lock for image '%s'" % id)
        unlock(lock_file)
        lock_file.close()

        if err:
            logger.critical("Error during deleting image.\n======\n{0}\n"+
                    "Exceptions:\n{1}".format(opstats, excepts))

    def truncate_image(self, image):
        "Remove image content but keep dataset"

        root = os.path.join(self._config["path_to_images_dir"], image)
        self._ensure_mounted(image)
        if not os.path.exists(root):
            raise ValueError("no such image: " + image)

        for node in glob.glob(os.path.join(root, "*")):
            if os.path.isdir(node) and not os.path.islink(node):
                shutil.rmtree(node)
            else:
                os.unlink(node)


    def get_free_space(self):
        "Return available space in pool"
        return 0 # FIXME: implement


class SimpleImageOperator(ImageOperator):

    def add_image(self, tarball, id):
        if not os.path.exists(tarball):
            raise Exception("Tarball not found: %s" % tarball) #TODO: proper exception type
        if id in self.list_images():
            raise Exception("Image %s already exists" % id)

        hashsum = get_hash(tarball)
        if not os.path.exists(self._config["path_to_images_dir"]):
            os.makedirs(self._config["path_to_images_dir"])

        compression = ""
        if tarball.endswith(".gz") or tarball.endswith(".tgz"):
            compression = "z"
        elif tarball.endswith(".bz2"):
            compression = "j"
        elif tarball.endswith(".xz"):
            compression = "J"
        command = "-x%sf" % compression

        destination = os.path.join(self._config["path_to_images_dir"], id)
        os.mkdir(destination)
        try:
            exec_(["tar", command, tarball, "-C", destination])
            with open(os.path.join(destination, "hash"), "w") as f:
                f.write(hashsum)
        except Exception as e:
            shutil.rmtree(destination)
            raise

    def delete_image(self, id):
        if id not in self.list_images():
            raise Exception("Image %s does not exist" % id)

        shutil.rmtree(os.path.join(self._config["path_to_images_dir"], id))


    def create_instance(self, id, pretty_name=None):
        if id not in self.list_images():
            raise Exception("Image %s not found" % id) #FIXME: proper exception
        orig_name = id + "." + datetime.datetime.now().strftime("%F.%H:%M:%S")
        if pretty_name is not None:
            orig_name = pretty_name + "@" + orig_name
        name = orig_name
        while name in self.list_instances():
            import random
            name = "%s.%d" % (orig_name, random.randint(0, 100))

        root = os.path.join(self._config["path_to_instances_dir"], name)
        try:
            exec_(["cp", "-a", os.path.join(self._config["path_to_images_dir"], id), root])
        except Exception as e:
            if os.path.exists(root):
                shutil.rmtree(root)
            raise

        return root

    def destroy_instance(self, path):
        if (os.path.abspath(os.path.dirname(path)) !=
                os.path.abspath(self._config["path_to_instances_dir"])):
            raise ValueError("Given path does not belong to heaver")
        id = os.path.basename(path)
        if id not in self.list_instances():
            raise Exception("Instance %s does not exist" % id)

        shutil.rmtree(path)

    def get_free_space(self):
        "Return available space on partition with instances"
        stat = os.statvfs(self._config["path_to_instances_dir"])
        return stat.f_bavail * stat.f_bsize / 1048576 # 1M


def get_image_operator(config):
    if config["fs_type"] == "zfs":
        klass = ZfsImageOperator
    elif config["fs_type"] == "simple":
        klass = SimpleImageOperator
    else:
        raise Exception("Invalid fs_type in config: %s" % config["fs_type"])

    return klass(config)

def extract_hashsum(url):
    parts = url.split(".")
    if len(parts) < 3:
        return None
    hash = parts[-2]
    if len(hash) != 40:
        return None
    return hash
