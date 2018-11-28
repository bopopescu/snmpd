#!/usr/bin/python
"""
http://snmplabs.com/pysnmp/examples/v3arch/asyncore/agent/cmdrsp/agent-side-mib-implementations.html

1. create MIB Py file and copy it to MIBSPY directory
   build-pysnmp-mib -o ../MIBSPY/MY-MIB.py MY-MIB.mib

2. sudo python <script_name>

3. Execute snmpwalk command (install snmp package for snmpwalk)
   snmpwalk -v 2c -c public localhost .1

"""
import logging
from pysnmp.entity import engine, config
from pysnmp import debug
from pysnmp.entity.rfc3413 import cmdrsp, context, ntforg
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import builder
from os import path, fork, getcwd, kill, remove, system
from signal import SIGTERM
from time import sleep
from sys import exit, stdout, stderr
import collections
from shutil import move
from optparse import OptionParser
from subprocess import Popen
from json import dumps, loads
import traceback

from constants import SERTCPCMD, SERIAL_LOGFILE, SNMP_LOGFILE, CONFFILE, PIDFILE, \
                      DEBUG, MODELFILE, DATACONF, SERIAL_TTY, LOG_BACKUP_COUNT, \
                      LOG_SIZE, CONFIG

CONFFILE = path.join(getcwd(), CONFFILE)
MibObject = collections.namedtuple('MibObject', ['mibName',
                                      'objectType', 'valueFunc', 'setFunc'])


def log(*msg):
    debug.logger and debug.logger(msg)
    stdout.flush()


def write_config(dic=None):
     try:
         with open("{0}_bk".format(DATACONF), 'w') as fp:
             if dic:
                 fp.write(dumps(dic, indent=True))
         move("{0}_bk".format(DATACONF), DATACONF)
     except Exception as e:
         log("Exception {0}".format(e))
         return False

     return True


def read_config():
    data = {}
    try:
        if path.exists(DATACONF):
            with open(DATACONF) as fp:
                data = loads(fp.read())
    except Exception as e:
        log('Not able to read configuration {0}'.format(e))

    return data


class SerialHTTPProcess(object):
    worker = {}

    def __init__(self, dir):
        fp = path.join(dir, SERIAL_LOGFILE)
        self.fp_log = open(fp, "w") if not path.exists(fp) else open(fp, "a")
        self.fp_log.write("\nInitialized SerialHTTPPRocess Instance")

    def get_data(self, key):                                                                                       
        data = read_config()                                                                                       
        if key in data:                                                                                            
            return data[key]                                                                                       
        else:                                                                                                      
            return '' 

    def start_serial(self, port):
        lport = '210{0}'.format(port)
        log("starting port lport {0} {1} port {2} parity {3} sbits {4} baud {5} dbits {6}".format(lport,
                                         SERIAL_TTY, port, self.get_data("{0}_{1}".format(port, 'parity')),
                                         self.get_data("{0}_{1}".format(port, 'sbits')),
                                         self.get_data("{0}_{1}".format(port, 'baud')),
                                         self.get_data("{0}_{1}".format(port, 'dbits'))
                                         ))
        self.run(port,
                 LOCALPORT= lport,
                 PARITY={'1': 'N',
                         '2': 'O',
                         '3': 'E'}[self.get_data("{0}_{1}".format(port, 'parity'))],
                 SBITS={'1': 1,
                        '1.5': 1.5,
                        '2': 2}[self.get_data("{0}_{1}".format(port, 'sbits'))],
                 DBITS=self.get_data("{0}_{1}".format(port, 'dbits')),
                 SERIALPORT="{0}{1}".format(SERIAL_TTY, port),
                 BAUDRATE=self.get_data("{0}_{1}".format(port, 'baud')))

    def run(self, port, **kw):
        """ Start a process as HTTP-to-Serial Bridge"""
        if not path.exists(kw['SERIALPORT']):
            return
          
        if port in self.worker.keys():
            self.terminate(port)

        cmd = "{0} -P {1} --parity {2} --sbits {3}".format(SERTCPCMD,
                                                           kw['LOCALPORT'],
                                                           kw['PARITY'],
                                                           kw['SBITS']
                                                           )
        cmd = "{0} --dbits {1} {2} {3}".format(cmd,
                                   kw['DBITS'],
                                   kw['SERIALPORT'],
                                   kw['BAUDRATE'])
        try:
            system('/bin/chmod +rw {0}'.format(kw['SERIALPORT']))
            self.fp_log.write("\nstarted subprocess {2} {0} pwd {1}".format(cmd,getcwd(), kw['BAUDRATE']))
            log("\nstarted subprocess {2} {0} pwd {1}".format(cmd,getcwd(), kw['BAUDRATE']))
            self.worker[port] = Popen([cmd],
                          shell=True,
                          stdout=self.fp_log,
                          stderr=self.fp_log,
                          stdin=self.fp_log,
                          cwd ='.'
                          )
        except Exception as e:
            if port in self.worker:
                del self.worker[port]
            self.fp_log.write("\nProcess is already running for %s \n %s " % (str(port), str(e)))

    def terminate(self, port):
        if port in self.worker.keys():
            self.fp_log.write("terminate port {0} with pid {0}".format(port, 
                                                                       self.worker[port].pid))
            self.worker[port].terminate()

    def get_status(self, port):
        """ Return True if There is not TCP connection with Client"""
        #if port in self.worker.keys() and self.worker[port]:
        log('Checking status {0}'.format(port))
        if path.exists(path.join(CONFIG, "210{0}".format(port))):
            return False

        return True


class PrivMib(object):
    """Stores the data we want to serve.
    """

    def __init__(self):
        self._TSAxonModel = self._getTSModel()

    def _getTSModel(self):
        if self._getmodel() in "Axon410":
            return "DataCaptor Terminal Server 400 Series"
        elif self._getmodel() in "Axon810":
            return "DataCaptor Terminal Server 800 Series"
        else:
            return "DataCaptor Terminal Server 100 Series"

    def _getmodel(self):
        return open(MODELFILE).read().strip() if path.exists(MODELFILE) else "Axon110"

    def get_len(self):
        if self._getmodel() in "Axon410":
            return 4
        elif self._getmodel() in "Axon810":
            return 8
        else:
            return 1

    def getTSAxonModel(self):
        return self._TSAxonModel

    def getAxonType(self):
        return self._getmodel()

    def getAxonError(self):
        return "NULL"


class SerialMib(object):
    def __init__(self, serialtcp, port=1):
        self._port = port
        self._serialtcp = serialtcp

        
    def get_data(self, key):
        data = read_config()
        if key in data:
            return data[key]
        else:
            return ''

    def set_data(self, key, value):
        data = read_config()
        if key in data:
            data[key] = value
            write_config(data)
            # restart serial port after setting
            if self._serialtcp.get_status(self._port):
                self._serialtcp.start_serial(self._port)

            return True
        else:
            return False

    def status(self, ret):
        return ret

    def getrs232PortInSpeed(self):
        """ .1.3.6.1.2.1.10.33.2.1.5.port#
        """
        #print("{0}_{1}".format(self._port, 'baud'), self.get_data("{0}_{1}".format(self._port, 'baud')))
        return self.get_data("{0}_{1}".format(self._port, 'baud')) if self.get_data("{0}_{1}".format(self._port, 'baud')) else str(11520)

    def getrs232PortOutSpeed(self):
        """ .1.3.6.1.2.1.10.33.2.1.6.port#
        """
        return self.get_data("{0}_{1}".format(self._port, 'baud')) if self.get_data("{0}_{1}".format(self._port, 'baud')) else str(11520)

    def getcharPortOperStatus(self):
        """ .1.3.6.1.2.1.19.2.1.7.port#
        val = 1  # UP if port is available for tcp connection
        val = 2  # 'DOWN' if port
        val = 3  # 'maintaince' maintenance mode
        val = 4  # 'absent' indicates that port hardware is not present.
        val = 5  # 'active' indicates up TCP connection is already
        """
        log('getcharPortOperStatus')
        lport = '210{0}'.format(self._port)
        if self._serialtcp.get_status(self._port):
            self._serialtcp.start_serial(self._port)

            return 1

        return 5

    def getcharPortInFlowType(self):
        """ .1.3.6.1.2.1.19.2.1.9.port#
        val = 1 # for 'none' indicates no flow control at this level
        val = 2 # for 'xonXoff' indicates software flow control by recognizing
        val = 3 # for 'hardware' indicates flow control delegated to lower level.
        val = 4 # for 'ctsRts'
        val = 5 # for 'dsrDtr'
        """
        val = int(self.get_data("{0}_{1}".format(self._port, 'fcontrol')) or 0)
        log('getcharPortInFlowType val {0}'.format(val))

        return val if val else 1

    def getcharPortOutFlowType(self):
        """ .1.3.6.1.2.1.19.2.1.10.port#
        val = 1 # for 'none' indicates no flow control at this level
        val = 2 # for 'xonXoff' indicates software flow control by recognizing
        val = 3 # for 'hardware' indicates flow control delegated to lower level.
        val = 4 # for 'ctsRts'
        val = 5 # for 'dsrDtr'
        """
        val = int(self.get_data("{0}_{1}".format(self._port, 'fcontrol')) or 0)
        log('getcharPortOutFlowType val {0}'.format(val))

        return val if val else 1

    def getrs232AsyncPortStopBits(self):
        """ .1.3.6.1.2.1.10.33.3.1.3.port#
        """
        val = int(self.get_data("{0}_{1}".format(self._port, 'sbits')) or 0)
        log('getrs232AsyncPortStopBits')
        return val if val else 1

    def getrs232AsyncPortBits(self):
        """ .1.3.6.1.2.1.10.33.3.1.2.port#

        :return:
        """
        val = int(self.get_data("{0}_{1}".format(self._port, 'dbits')) or 0)
        log('getrs232AsyncPortBits')
        return 8 if not val else val

    def getrs232PortOutFlowType(self):
        """ .1.3.6.1.2.1.10.33.2.1.8.port#
        val = 1  # for None or Software
        val = 2  # for 'Hardware'
        """
        log('getrs232PortOutFlowType')
        val = int(self.get_data("{0}_{1}".format(self._port, 'fcontrol')) or 0)
        return 1 if val == 0 else val

    def getrs232PortInFlowType(self):
        """ .1.3.6.1.2.1.10.33.3.1.7.port#
        """

        val = int(self.get_data("{0}_{1}".format(self._port, 'fcontrol')) or 0)
        log('getrs232PortInFlowType val {0}'.format(val))
        return val if val else 1

    def getrs232AsyncPortParity(self):
        """ .1.3.6.1.2.1.10.33.3.1.4.port#
        val = 1  # for None
        val = 2  # for Odd
        val = 3  # for Even
        """
        val = int(self.get_data("{0}_{1}".format(self._port, 'parity')) or 1)
        log('getrs232AsyncPortParity val {0}'.format(val))
        return val if val else 1

    def setrs232AsyncPortBits(self, val):
        """ .1.3.6.1.2.1.10.33.3.1.2.port#

        :return:
        """

        log('setrs232AsyncPortBits val {0}'.format(val))
        val = str(val).split('(')[0]

        return self.set_data("{0}_{1}".format(self._port, 'dbits'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'dbits')))
        

    def setcharPortInFlowType(self, val):
        """ .1.3.6.1.2.1.19.2.1.9.port#
        val = 1 # for 'none' indicates no flow control at this level
        val = 2 # for 'xonXoff' indicates software flow control by recognizing
        val = 3 # for 'hardware' indicates flow control delegated to lower level.
        val = 4 # for 'ctsRts'
        val = 5 # for 'dsrDtr'
        """
        log('setcharPortInFlowType val {0}'.format(val))
        val = str(val).split('(')[0]

        return self.set_data("{0}_{1}".format(self._port, 'fcontrol'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'fcontrol')))

    def setrs232PortInSpeed(self, val):
        log('setrs232PortInSpeed val {0}'.format(val))
        val = str(val).split('(')[0]

        return self.set_data("{0}_{1}".format(self._port, 'baud'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'baud')))

    def setrs232PortOutSpeed(self, val):
        log('setrs232PortOutSpeed val {0}'.format(val))
        val = str(val).split('(')[0]

        return self.set_data("{0}_{1}".format(self._port, 'baud'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'baud')))

    def setcharPortOutFlowType(self, val):
        """ .1.3.6.1.2.1.19.2.1.10.port#
        val = 1 # for 'none' indicates no flow control at this level
        val = 2 # for 'xonXoff' indicates software flow control by recognizing
        val = 3 # for 'hardware' indicates flow control delegated to lower level.
        val = 4 # for 'ctsRts'
        val = 5 # for 'dsrDtr'
        """
        log('setcharPortOutFlowType val {0}'.format(val))
        val = str(val).split('(')[0]
        return self.set_data("{0}_{1}".format(self._port, 'fcontrol'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'fcontrol')))

    def setrs232AsyncPortStopBits(self, val):
        """ .1.3.6.1.2.1.10.33.3.1.3.port#
        """
        log('setrs232AsyncPortStopBits val {0}'.format(val))
        val = str(val).split('(')[0]
        return self.set_data("{0}_{1}".format(self._port, 'sbits'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'sbits')))

    def setrs232PortOutFlowType(self, val):
        """ .1.3.6.1.2.1.10.33.2.1.8.port#
        val = 1  # for None or Software
        val = 2  # for 'Hardware'
        """
        log('setrs232PortOutFlowType val {0}'.format(val))
        val = str(val).split('(')[0]
        return self.set_data("{0}_{1}".format(self._port, 'fcontrol'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'fcontrol')))

    def setrs232PortInFlowType(self, val):
        """ .1.3.6.1.2.1.10.33.3.1.7.port#
        """
        log('setrs232PortInFlowType val {0}'.format(val))
        val = str(val).split('(')[0]
        return self.set_data("{0}_{1}".format(self._port, 'fcontrol'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'fcontrol')))

    def setrs232AsyncPortParity(self, val):
        """ .1.3.6.1.2.1.10.33.3.1.4.port#
        val = 1  # for None
        val = 2  # for Odd
        val = 3  # for Even
        """
        log('setrs232AsyncPortParity val {0}'.format(val))
        val = str(val).split('(')[0]
        return self.set_data("{0}_{1}".format(self._port, 'parity'),
                             val if val else self.get_data("{0}_{1}".format(self._port, 'parity')))

def createVariable(SuperClass, getValue, setValue, *args):

    class Var(SuperClass):
        def readGet(self, name, *args):
            return name, self.syntax.clone(getValue())

        #def writeTest(self, name, *args):
        #    log("Write Testing")

        def writeCommit(self, name, val, *args):
            log(" Setting var...{0} {1} {2}".format(name, val, setValue))
            if setValue:
                setValue(val)

    return Var(*args)


class SNMPAgent(object):
    """Implements an Agent that serves the custom MIB and
    can send a trap.
    """

    def _read_conf(self):
        self._CONF = {}
        if path.exists(CONFFILE):
            self._CONF = eval(open(CONFFILE).read())
        log(self._CONF, CONFFILE, getcwd())

    def __init__(self):

        #each SNMP-based application has an engine
        self._snmpEngine = engine.SnmpEngine()
        
        # Reading configuration
        self._read_conf()

        self._serialtcp = SerialHTTPProcess(self._CONF['LOG_DIR'] if 'LOG_DIR' in self._CONF else '')
        
        #open a UDP socket to listen for snmp requests
        port = int(self._CONF['PORT']) if 'PORT' in self._CONF and self._CONF['PORT'] else 161
        config.addSocketTransport(self._snmpEngine, udp.domainName,
                                  udp.UdpTransport().openServerMode(('0.0.0.0', port)))

        #add a v2 user with the community string public
        config.addV1System(self._snmpEngine, "read-area",
                           self._CONF['PUBLIC'] if 'PUBLIC' in self._CONF and self._CONF['PUBLIC'] else "public")
        config.addV1System(self._snmpEngine, 'write-area',
                           self._CONF['PRIVATE'] if 'PRIVATE' in self._CONF and self._CONF['PRIVATE'] else 'private')

        #let anyone accessing 'public' read anything in the subtree below,
        #which is the enterprises subtree that we defined our MIB to be in
        config.addVacmUser(self._snmpEngine, 1, "read-area", "noAuthNoPriv",
                           readSubTree=(1, 3, 6, 1, 2))
        #config.addVacmUser(self._snmpEngine, 1, "read-area", "noAuthNoPriv",
        #                   readSubTree=(1, 3, 6, 1, 2, 1, 19, 2, 1))
        config.addVacmUser(self._snmpEngine, 1, "read-area", "noAuthNoPriv",
                           readSubTree=(1, 3, 6, 1, 4, 1, 332, 11))


        config.addVacmUser(self._snmpEngine, 2, "read-area", "noAuthNoPriv",
                           readSubTree=(1,3,6,1,2,1,10,33))
        config.addVacmUser(self._snmpEngine, 2, "read-area", "noAuthNoPriv",
                           readSubTree=(1,3,6,1,2,1,19,2,1))
        config.addVacmUser(self._snmpEngine, 2, "read-area", "noAuthNoPriv",
                           readSubTree=(1, 3, 6, 1, 4, 1, 332, 11))

        # Write Subtree
        log('before enable write-area')
        if self._CONF and 'ALLOW' in self._CONF and self._CONF['ALLOW'].lower() in 'true':
            log('Adding Write community with write-area')
            config.addVacmUser(self._snmpEngine, 1, 'write-area', 'noAuthNoPriv',
                               readSubTree=(1, 3, 6, 1, 2, 1, 10, 33), writeSubTree=(1, 3, 6, 1, 2, 1, 10, 33))
            config.addVacmUser(self._snmpEngine, 2, 'write-area', 'noAuthNoPriv',
                               readSubTree=(1, 3, 6, 1, 2, 1, 10, 33), writeSubTree=(1, 3, 6, 1, 2, 1, 10, 33))
            config.addVacmUser(self._snmpEngine, 1, 'write-area', 'noAuthNoPriv',
                               readSubTree=(1,3,6,1,2,1,19,2,1), writeSubTree=(1,3,6,1,2,1,19,2,1))
            config.addVacmUser(self._snmpEngine, 2, 'write-area', 'noAuthNoPriv',
                               readSubTree=(1,3,6,1,2,1,19,2,1), writeSubTree=(1,3,6,1,2,1,19,2,1))

        #each app has one or more contexts
        self._snmpContext = context.SnmpContext(self._snmpEngine)

        #the builder is used to load mibs. tell it to look in the
        #MIBS directory for our new MIB. We'll also use it to
        #export our symbols later
        mibBuilder = self._snmpContext.getMibInstrum().getMibBuilder()
        pub = path.join(getcwd(), 'PYSNMP_MIBS')
        priv = path.join(getcwd(), 'MIBSPY')
        mibSources = mibBuilder.getMibSources() + (builder.DirMibSource(pub),) + (builder.DirMibSource(priv),)
        mibBuilder.setMibSources(*mibSources)

        #export our custom mib
        self._exportprivMIBS(mibBuilder)
        self._exportpubMIBS(mibBuilder)

        # tell pysnmp to respotd to get, getnext, set and getbulk
        cmdrsp.GetCommandResponder(self._snmpEngine, self._snmpContext)
        cmdrsp.NextCommandResponder(self._snmpEngine, self._snmpContext)
        cmdrsp.SetCommandResponder(self._snmpEngine, self._snmpContext)
        cmdrsp.BulkCommandResponder(self._snmpEngine, self._snmpContext)


    def _exportprivMIBS(self, mibBuilder):

        MibScalarInstance, = mibBuilder.importSymbols('SNMPv2-SMI',
                                                      'MibScalarInstance')

        mib = PrivMib()
        objects = [MibObject('AXON-MIB', 'digiEsSnmpOidModel', mib.getTSAxonModel, None),
                   MibObject('AXON-MIB', 'digiSnmpOidType', mib.getAxonType, None),
                   MibObject('AXON-MIB', 'digiSnmpOidModel', mib.getAxonError, None),
                   ]

        for mibObject in objects:
            nextVar, = mibBuilder.importSymbols(mibObject.mibName,
                                                mibObject.objectType)

            instance = createVariable(MibScalarInstance,
                                      mibObject.valueFunc, mibObject.setFunc,
                                      nextVar.name, (0,) if mibObject.objectType in 'digiEsSnmpOidModel' else (),
                                      nextVar.syntax)

            #need to export as <var name>Instance
            instanceDict = {str(nextVar.name)+"Instance":instance}
            mibBuilder.exportSymbols(mibObject.mibName,
                                     **instanceDict)

    def _exportpubMIBS(self, mibBuilder):

        rs232port = [
                   MibObject('RS-232-MIB', 'rs232PortInSpeed', 'getrs232PortInSpeed', 'setrs232PortInSpeed'),
                   MibObject('RS-232-MIB', 'rs232PortOutSpeed', 'getrs232PortOutSpeed', 'setrs232PortOutSpeed'),
                   MibObject('RS-232-MIB', 'rs232PortOutFlowType', 'getrs232PortOutFlowType', 'setrs232PortOutFlowType', ),
                   MibObject('RS-232-MIB', 'rs232PortInFlowType', 'getrs232PortInFlowType', 'setrs232PortInFlowType'),
                   ]
        rs232async = [
                   MibObject('RS-232-MIB', 'rs232AsyncPortParity', 'getrs232AsyncPortParity', 'setrs232AsyncPortParity'),
                   MibObject('RS-232-MIB', 'rs232AsyncPortStopBits', 'getrs232AsyncPortStopBits', 'setrs232AsyncPortStopBits'),
                   MibObject('RS-232-MIB', 'rs232AsyncPortBits', 'getrs232AsyncPortBits', 'setrs232AsyncPortBits'),
                   ]
        portstatus = [
                   MibObject('RFC1316-MIB', 'charPortOperStatus', 'getcharPortOperStatus', None),
                   MibObject('RFC1316-MIB', 'charPortInFlowType', 'getcharPortInFlowType', 'setcharPortInFlowType'),
                   MibObject('RFC1316-MIB', 'charPortOutFlowType', 'getcharPortOutFlowType', 'setcharPortOutFlowType'),
                   ]

        mib = PrivMib()
        ports = mib.get_len()

        (MibTable,
         MibTableRow,
         MibTableColumn,
         MibScalarInstance) = mibBuilder.importSymbols(
            'SNMPv2-SMI',
            'MibTable',
            'MibTableRow',
            'MibTableColumn',
            'MibScalarInstance'
        )

        (rs232PortEntry,
         rs232PortIndex,
         rs232PortInSpeed) = mibBuilder.importSymbols(
            'RS-232-MIB',
            'rs232PortEntry',
            'rs232PortIndex',
            'rs232PortInSpeed'
        )

        try:
            for port in range(1, ports + 1):
                log("Data for port {0}".format(port))
                smib = SerialMib(self._serialtcp, port)
                self._serialtcp.start_serial(port)

                for obj in rs232port + portstatus + rs232async:
                    log("{0} -- {1}".format(port, obj.objectType))
                    rowInstanceId = rs232PortEntry.getInstIdFromIndices(port)
                    nextVar, = mibBuilder.importSymbols(obj.mibName,
                                                obj.objectType)
                    instance = createVariable(MibScalarInstance,
                                          getattr(smib, obj.valueFunc),
                                          getattr(smib, obj.setFunc) if obj.setFunc else obj.setFunc,
                                          nextVar.name, rowInstanceId,
                                          nextVar.syntax)


                    instanceDict = {str(nextVar.name + rowInstanceId) +  "Instance": instance}
                    mibBuilder.exportSymbols(obj.mibName,
                                         **instanceDict)

        except Exception as e:
            log('Exception Error: In Function pub_mib Export {0} \n'.format(e))
            traceback.format_exc()

    def serve_forever(self):
        self._snmpEngine.transportDispatcher.jobStarted(1)
        try:
           self._snmpEngine.transportDispatcher.runDispatcher()
        except:
            self._snmpEngine.transportDispatcher.closeDispatcher()
            raise


def main():
    agent = SNMPAgent()
    try:
        agent.serve_forever()
    except KeyboardInterrupt:
        log ("Shutting down SNMP Agent")



def start():
    global PIDFILE
    if path.exists(PIDFILE):
        log("PID {0} - CONFfile {1}".format(PIDFILE, CONFFILE))
        return

    log("PID FILE {0}-{1}".format(PIDFILE, path.exists(PIDFILE)))
    pid = fork()
    if pid:
        with open(PIDFILE, 'w+') as pf:
            pf.write(str(pid))
        exit(0)
    else:
        # Child Process
        try:
            log("Starting snmp process inside child")
            main()
        except Exception as e:
            log("Exception: {0}".format(e))
            stop()
            raise Exception(e)


def stop():
    global PIDFILE
    if not path.exists(CONFFILE):
        CONF = {}
    else:
        CONF = eval(open(CONFFILE).read())
    if not path.exists(PIDFILE):
        return

    pid = int(open(PIDFILE).read())
    try:
        kill(pid, SIGTERM)
        system("/usr/bin/fuser -k {0}/udp".format(CONF['PORT'] if 'PORT' in CONF else 161))
    except:
        log("not able to kill process")

    log("SNMP Process stopped with pid- {0}".format(PIDFILE))
    if path.exists(PIDFILE):
        remove(PIDFILE)

def logger():
    if not path.exists(CONFFILE):
        CONF = {}
    else:
        CONF = eval(open(CONFFILE).read())
    fp = path.join(CONF['LOG_DIR'] if 'LOG_DIR' in CONF else '',
                       SNMP_LOGFILE)
    a = 'a'
    if not path.exists(fp):
        a = 'w'

    stderr = open(fp, a) 
    stdout = stderr

    p = debug.Printer(handler=logging.StreamHandler(stream=stderr))
    debug.setLogger(debug.Debug(DEBUG, printer=p))#'msgproc', 'dsp', 'io', 'app', flagIns))

    global PIDFILE
    PIDFILE = path.join(getcwd(),
                            CONF['PID_DIR'] if 'PID_DIR' in CONF else 'pids',
                            PIDFILE)
      
if __name__ == '__main__':

    usage = "axonsnmp.py --[start/stop/restart]"
    parser = OptionParser(usage)
    parser.add_option("-s",
                      "--start",
                      dest="start",
                      help="Start process")

    parser.add_option("-m",
                      "--stop",
                      dest="stop",
                      help="Stop process")

    parser.add_option("-r",
                      "--restart",
                      dest="restart",
                      help="Restart process")

    options, args = parser.parse_args()

    logger()
    if options.start is not None:
        start()

    elif options.stop is not None:
        stop()

    elif options.restart is not None:
        stop()
        sleep(1)
        start()
    else:
        parser.print_help()
    exit(0)

