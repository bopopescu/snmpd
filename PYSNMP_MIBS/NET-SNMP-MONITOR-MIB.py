# PySNMP SMI module. Autogenerated from smidump -f python NET-SNMP-MONITOR-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:57 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( netSnmpModuleIDs, netSnmpObjects, ) = mibBuilder.importSymbols("NET-SNMP-MIB", "netSnmpModuleIDs", "netSnmpObjects")
( Bits, Integer32, Integer32, ModuleIdentity, MibIdentifier, NotificationType, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Integer32", "Integer32", "ModuleIdentity", "MibIdentifier", "NotificationType", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks")
( DisplayString, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString")

# Objects

nsProcess = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 1, 21))
nsDisk = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 1, 22))
nsFile = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 1, 23))
nsLog = MibIdentifier((1, 3, 6, 1, 4, 1, 8072, 1, 24))
netSnmpMonitorMIB = ModuleIdentity((1, 3, 6, 1, 4, 1, 8072, 3, 1, 3)).setRevisions(("2002-02-09 00:00",))
if mibBuilder.loadTexts: netSnmpMonitorMIB.setOrganization("www.net-snmp.org")
if mibBuilder.loadTexts: netSnmpMonitorMIB.setContactInfo("postal:   Wes Hardaker\nP.O. Box 382\nDavis CA  95617\n\nemail:    net-snmp-coders@lists.sourceforge.net")
if mibBuilder.loadTexts: netSnmpMonitorMIB.setDescription("Configured elements of the system to monitor\n(XXX - ugh! - need a better description!)")

# Augmentions

# Exports

# Module identity
mibBuilder.exportSymbols("NET-SNMP-MONITOR-MIB", PYSNMP_MODULE_ID=netSnmpMonitorMIB)

# Objects
mibBuilder.exportSymbols("NET-SNMP-MONITOR-MIB", nsProcess=nsProcess, nsDisk=nsDisk, nsFile=nsFile, nsLog=nsLog, netSnmpMonitorMIB=netSnmpMonitorMIB)

