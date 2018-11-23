
SERTCPCMD = './serial_to_tcp.py'
SERIAL_LOGFILE = "SerialHTTP.log"
SNMP_LOGFILE = 'snmpd.log'
#debug.setLogger(debug.Debug('all'))

CONFIG = 'config'
CONFFILE = 'etc/snmp.conf'
PIDFILE = 'snmp.pid'
MODELFILE = './etc/model'
DATACONF = '{0}/config.json'.format(CONFIG)
SERIAL_TTY = '/dev/ttymxc'
LOG_BACKUP_COUNT = 5
LOG_SIZE = 10000
DEBUG = 'mibview'

"""
Debug flags
--------------
io
dsp
msgproc
secmod
mibbuild
mibview
mibinstrum
acl
proxy
app
all
--------------
"""