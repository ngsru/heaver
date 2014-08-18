# -*- coding: utf-8 -*-

from flask import Flask, redirect
import sys
import subprocess

app = Flask(__name__)


#pidfile = open("/tmp/heaver/microweb_" + str(sys.argv[2]) + "_heaver.pid", "w")
#pidfile.write(str(os.getpid()))
#pidfile.close()

host = '0.0.0.0'
port = int(sys.argv[1])

header = """
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Перегрузка!</title>
<style>
    body {
        width: 1024px;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
    table {
	border-collapse: collapse;
    }
    td {
	border: 1px solid grey;
	cellspacing: 0px;
    }
</style>
</head>
<body>
<h1>Сервер перегружен!</h1>
<p>В контейнере закончилась оперативная память, поэтому процессы внутри него были приостановлены.</p>
<p>Ниже отображен перечень процессов, которые были запущены на момент инцидента.</p>
<p>Обратитесь к разработчику проекта для решения данной проблемы.</p>
<p>Доступ по ssh заморожен не был, чтобы освободить ресурсы вы можете завершить избыточные процессы через ssh.</p>

"""

footer = """
</body>
</html>
"""

def exec_cmd(cmd, stdin=""):
    "Execute given cmd and optionally stdin, return exit code, stdout, stderr"
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(stdin)
    exit_code = process.returncode
    return exit_code, stdout, stderr



@app.route('/kill/<string:pid>')
def kill(pid):
    exec_cmd(["/usr/bin/kill", pid])
    return redirect("/")


@app.route('/kill_force/<string:pid>')
def kill_force(pid):
    exec_cmd(["/usr/bin/kill", "-9", pid])
    return redirect("/")


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def index(path):
    output = header
    output += "<p><b>Дерево процессов:</b></p>"
    exit_code, stdout, stderr = exec_cmd(["/usr/bin/ps", "-o", "cgroup", "--no-headers", sys.argv[2]])
    cgroup = stdout.strip()
    exit_code, stdout, stderr = exec_cmd(["/usr/bin/ps", "-o", "pid,cgroup", "--no-headers", "ax"])
    stdout = stdout.split('\n')
    pidlist = []
    for line in stdout:
	if cgroup in line:
	    pidlist.append(line.split()[0])


    exit_code, stdout, stderr = exec_cmd(["/usr/bin/ps", "f", "-o", "command", "--no-headers"] + pidlist)
    commands = stdout.split('\n')
    # execute ps for pidlist
    exit_code, stdout, stderr = exec_cmd(["/usr/bin/ps", "f", "-o", "pid,user,pcpu,size,vsize", "--no-headers"] + pidlist)
    ps = stdout.split('\n')
    table = "<table style=\"width:100%;\">"
    table += "<td style=\"text-align: center;\">Process ID</td>"
    table += "<td style=\"text-align: center;\">User</td>"
    table += "<td style=\"text-align: center;\">CPU Usage %</td>"
    table += "<td style=\"text-align: center;\">Memory usage</td>"
    table += "<td style=\"text-align: center;\">Virtual memory usage</td>"
    table += "<td style=\"text-align: center;\">Command</td>"
    table += "<td style=\"text-align: center;\">Действия</td>"
    i = 0
    for line in ps:
	columns = line.split()
	if len(columns)==5:
	    table += "<tr>"
	    table += "<td style=\"text-align: center;\">%s</td>" % columns[0]
	    table += "<td style=\"text-align: center;\">%s</td>" % columns[1]
	    table += "<td style=\"text-align: center;\">%s</td>" % columns[2]
	    table += "<td style=\"text-align: center;\">%4.2f Mb</td>" % (float(columns[3].strip())/1024.0)
    	    table += "<td style=\"text-align: center;\">%4.2f Mb</td>" % (float(columns[4].strip())/1024.0)
	    table += "<td style=\"text-align: left; font-size: 16px;\"><xmp>%s</xmp></td>" % commands[i]
	    table += "<td style=\"text-align: center; font-size: 11px;\">"
	    table += "<a href=\"/kill/%s\" onclick=\"return confirm('Уверены, что хотите убить %s?');\">Убить</a><br/>" % (columns[0], commands[i])
	    table += "<a href=\"/kill_force/%s\" onclick=\"return confirm('Уверены, что хотите убить %s с особой жестокостью?');\">Убить с особой жестокостью</a></td>" % (columns[0], commands[i])
	    table += "</tr>"
	i += 1
    
    table += "</table>"
        
    output += table
    output += footer
    return output

    
if __name__ == "__main__":
    app.debug = False
    app.run(host=host, port=port)
