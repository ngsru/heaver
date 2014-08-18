import setuptools

setuptools.setup(
    name="heaver",
    version="0.1",
    description="lxc container management tool",
    author="Vladimir Petrov",
    author_email="v.petrov@office.ngs.ru",
    packages=setuptools.find_packages(),
    data_files=[("/etc/cron.d", ["cron/heaver-send-status"]),
        ("/var/lib/heaver", []),
        ("/var/log/heaver", []),
        ("/etc/heaver", ["config/worker.yml", "config/client.yml", "config/daemon.yml"]),
        ("/etc/heaver/hooks", ["config/hooks/start_hook", "config/hooks/stop_hook"]),
        ("/etc/heaver/hooks/extra", ["config/hooks/extra/microwebserver.py"])],
    entry_points=dict(console_scripts=["heaver = heaver.cli.bootstrap:bootstrap",
                                       "heaver-img = heaver.cli.bootstrap:bootstrap_imager",
                                       "heaverd = heaver.cli.bootstrap:bootstrap_daemon",
                                       "heaverc = heaver.cli.bootstrap:bootstrap_client"]))
