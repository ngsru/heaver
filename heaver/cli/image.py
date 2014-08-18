import heaver.cli.report as report
import heaver.image as image


def main(args, config):

    if not (args.create or args.destroy or args.add or args.remove or args.list or args.sync):
        report.die("No action given")

    if args.list and (args.create or args.destroy or args.add or args.remove):
        report.die("Cannot show list and perform actions!")

    if args.create and args.destroy:
        report.die("Cannot create and destroy clone simultaneously (-CD given)")

    if args.add and args.remove:
        report.die("Cannot add and remove image simultaneously (-AR given)")

    operator = image.get_image_operator(config["image"])

    if args.sync:
        sync(operator, args)

    if args.list:
        list_images(operator, args)

    if args.add:
        add(operator, args)

    if args.create:
        create(operator, args)

    if args.destroy:
        destroy(operator, args)

    if args.remove:
        remove(operator, args)


def sync(operator, args):
    if (args.image and args.all) or (not args.image and not args.all):
        report.die("Either all or one concrete image may be syncronized")

    if args.image:
        images = [args.image]

    if args.all:
        images = operator.list_images()

    result = operator.sync_images(images)
    for image, status in result:
        print report.format(dict(action="sync", status=("FAIL" if status == "error" else "OK"),
                                 data=[image, status], message="%s\t%s" % (image, status)))

def list_images(operator, args):
    images = operator.list_images()
    for image in images:
        print report.format(dict(action="list", status="OK", data=[image], message=image))

def create(operator, args):
    if not args.image:
        report.die("Image id must be specified")

    try:
        instance = operator.create_instance(args.image, args.clone)
        print report.format(dict(action="create", status="OK", data=[args.image, instance],
            message="Created instance of image %s: %s" % (args.image, instance)))
    except Exception as e:
        report.die("Failed to create instance for image %s: %s" % (args.image, e))


def destroy(operator, args):
    if not args.clone:
        report.die("Clone id must be specified")

    try:
        instance = operator.destroy_instance(args.clone)
        print report.format(dict(action="destroy", status="OK", data=[args.clone],
            message="Destroyed instance %s" % (args.clone,)))
    except Exception as e:
        report.die("Failed to destroy instance %s: %s" % (args.clone, e))


def add(operator, args):
    if not args.image:
        report.die("Image id must be specified")
    if not args.tarball:
        report.die("Tarball with image must be specified")

    try:
        operator.add_image(args.tarball, args.image)
        print report.format(dict(action="add", status="OK", data=args.image,
            message="Added image %s from '%s'" % (args.image, args.tarball)))
    except Exception as e:
        report.die("Failed to add image %s from '%s': %s" % (args.image, args.tarball, e))

def remove(operator, args):
    if not args.image:
        report.die("Image id must be specified")

    try:
        instance = operator.delete_image(args.image)
        print report.format(dict(action="remove", status="OK", data=[args.image],
            message="Removed image %s" % (args.image,)))
    except Exception as e:
        report.die("Failed to remove image %s: %s" % (args.image, e))
