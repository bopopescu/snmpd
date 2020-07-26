# PySNMP SMI module. Autogenerated from smidump -f python VRRP-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:49 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( ifIndex, ) = mibBuilder.importSymbols("IF-MIB", "ifIndex")
( ModuleCompliance, NotificationGroup, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "NotificationGroup", "ObjectGroup")
( Bits, Counter32, Integer32, Integer32, IpAddress, ModuleIdentity, MibIdentifier, NotificationType, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Counter32", "Integer32", "Integer32", "IpAddress", "ModuleIdentity", "MibIdentifier", "NotificationType", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "mib-2")
( MacAddress, RowStatus, TextualConvention, TimeStamp, TruthValue, ) = mibBuilder.importSymbols("SNMPv2-TC", "MacAddress", "RowStatus", "TextualConvention", "TimeStamp", "TruthValue")

# Types

class VrId(Integer32):
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(1,255)
    

# Objects

vrrpMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 68)).setRevisions(("2000-03-03 00:00",))
if mibBuilder.loadTexts: vrrpMIB.setOrganization("IETF VRRP Working Group")
if mibBuilder.loadTexts: vrrpMIB.setContactInfo("Brian R. Jewell\nPostal: Copper Mountain Networks, Inc.\n        2470 Embarcadero Way\n        Palo Alto, California 94303\nTel:    +1 650 687 3367\nE-Mail: bjewell@coppermountain.com")
if mibBuilder.loadTexts: vrrpMIB.setDescription("This MIB describes objects used for managing Virtual Router\nRedundancy Protocol (VRRP) routers.")
vrrpNotifications = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 0))
vrrpOperations = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 1))
vrrpNodeVersion = MibScalar((1, 3, 6, 1, 2, 1, 68, 1, 1), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpNodeVersion.setDescription("This value identifies the particular version of the VRRP\nsupported by this node.")
vrrpNotificationCntl = MibScalar((1, 3, 6, 1, 2, 1, 68, 1, 2), Integer().subtype(subtypeSpec=SingleValueConstraint(2,1,)).subtype(namedValues=NamedValues(("enabled", 1), ("disabled", 2), )).clone(1)).setMaxAccess("readwrite")
if mibBuilder.loadTexts: vrrpNotificationCntl.setDescription("Indicates whether the VRRP-enabled router will generate\nSNMP traps for events defined in this MIB. 'Enabled'\nresults in SNMP traps; 'disabled', no traps are sent.")
vrrpOperTable = MibTable((1, 3, 6, 1, 2, 1, 68, 1, 3))
if mibBuilder.loadTexts: vrrpOperTable.setDescription("Operations table for a VRRP router which consists of a\nsequence (i.e., one or more conceptual rows) of\n'vrrpOperEntry' items.")
vrrpOperEntry = MibTableRow((1, 3, 6, 1, 2, 1, 68, 1, 3, 1)).setIndexNames((0, "IF-MIB", "ifIndex"), (0, "VRRP-MIB", "vrrpOperVrId"))
if mibBuilder.loadTexts: vrrpOperEntry.setDescription("An entry in the vrrpOperTable containing the operational\ncharacteristics of a virtual router. On a VRRP router,\na given virtual router is identified by a combination\nof the IF index and VRID.\n\nRows in the table cannot be modified unless the value\nof `vrrpOperAdminState' is `disabled' and the\n`vrrpOperState' has transitioned to `initialize'.")
vrrpOperVrId = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 1), VrId()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: vrrpOperVrId.setDescription("This object contains the Virtual Router Identifier (VRID).")
vrrpOperVirtualMacAddr = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 2), MacAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpOperVirtualMacAddr.setDescription("The virtual MAC address of the virtual router. Although this\nobject can be derived from the 'vrrpOperVrId' object, it is\ndefined so that it is easily obtainable by a management\napplication and can be included in VRRP-related SNMP traps.")
vrrpOperState = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 3), Integer().subtype(subtypeSpec=SingleValueConstraint(1,3,2,)).subtype(namedValues=NamedValues(("initialize", 1), ("backup", 2), ("main", 3), ))).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpOperState.setDescription("The current state of the virtual router. This object has\nthree defined values:\n\n  - `initialize', which indicates that all the\n    virtual router is waiting for a startup event.\n\n  - `backup', which indicates the virtual router is\n    monitoring the availability of the main router.\n\n  - `main', which indicates that the virtual router\n    is forwarding packets for IP addresses that are\n    associated with this router.\n\nSetting the `vrrpOperAdminState' object (below) initiates\ntransitions in the value of this object.")
vrrpOperAdminState = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 4), Integer().subtype(subtypeSpec=SingleValueConstraint(2,1,)).subtype(namedValues=NamedValues(("up", 1), ("down", 2), )).clone(2)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperAdminState.setDescription("This object will enable/disable the virtual router\nfunction. Setting the value to `up', will transition\nthe state of the virtual router from `initialize' to `backup'\nor `main', depending on the value of `vrrpOperPriority'.\nSetting the value to `down', will transition  the\nrouter from `main' or `backup' to `initialize'. State\ntransitions may not be immediate; they sometimes depend on\nother factors, such as the interface (IF) state.\n\nThe `vrrpOperAdminState' object must be set to `down' prior\nto modifying the other read-create objects in the conceptual\nrow. The value of the `vrrpOperRowStatus' object (below)\nmust be `active', signifying that the conceptual row\nis valid (i.e., the objects are correctly set),\nin order for this object to be set to `up'.")
vrrpOperPriority = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 5), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 255)).clone(100)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperPriority.setDescription("This object specifies the priority to be used for the\nvirtual router main election process. Higher values imply\nhigher priority.\n\nA priority of '0', although not settable, is sent by\nthe main router to indicate that this router has ceased\nto participate in VRRP and a backup virtual router should\ntransition  to become a new main.\n\nA priority of 255 is used for the router that owns the\nassociated IP address(es).")
vrrpOperIpAddrCount = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 6), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 255))).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpOperIpAddrCount.setDescription("The number of IP addresses that are associated with this\nvirtual router. This number is equal to the number of rows\nin the vrrpAssoIpAddrTable that correspond to a given IF\nindex/VRID pair.")
vrrpOperMainIpAddr = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 7), IpAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpOperMainIpAddr.setDescription("The main router's real (primary) IP address. This is\nthe IP address listed as the source in VRRP advertisement\nlast received by this virtual router.")
vrrpOperPrimaryIpAddr = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 8), IpAddress().clone("0.0.0.0")).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperPrimaryIpAddr.setDescription("In the case where there is more than one IP address for\na given `ifIndex', this object is used to specify the IP\naddress that will become the `vrrpOperMainIpAddr', should\nthe virtual router transition from backup to main. If\nthis object is set to 0.0.0.0, the IP address which is\nnumerically lowest will be selected.")
vrrpOperAuthType = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 9), Integer().subtype(subtypeSpec=SingleValueConstraint(1,3,2,)).subtype(namedValues=NamedValues(("noAuthentication", 1), ("simpleTextPassword", 2), ("ipAuthenticationHeader", 3), )).clone(1)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperAuthType.setDescription("Authentication type used for VRRP protocol exchanges between\nvirtual routers. This value of this object is the same for a\ngiven ifIndex.\n\nNew enumerations to this list can only be added via a new\nRFC on the standards track.")
vrrpOperAuthKey = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 10), OctetString().subtype(subtypeSpec=ValueSizeConstraint(0, 16))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperAuthKey.setDescription("The Authentication Key. This object is set according to\nthe value of the 'vrrpOperAuthType' object\n('simpleTextPassword' or 'ipAuthenticationHeader'). If the\nlength of the value is less than 16 octets, the agent will\nleft adjust and zero fill to 16 octets. The value of this\nobject is the same for a given ifIndex.\n\nWhen read, vrrpOperAuthKey always returns an Octet String\nof length zero.")
vrrpOperAdvertisementInterval = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 11), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 255)).clone(1)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperAdvertisementInterval.setDescription("The time interval, in seconds, between sending\nadvertisement messages. Only the main router sends\nVRRP advertisements.")
vrrpOperPreemptMode = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 12), TruthValue().clone('true')).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperPreemptMode.setDescription("Controls whether a higher priority virtual router will\npreempt a lower priority main.")
vrrpOperVirtualRouterUpTime = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 13), TimeStamp()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpOperVirtualRouterUpTime.setDescription("This is the value of the `sysUpTime' object when this\nvirtual router (i.e., the `vrrpOperState') transitioned\nout of `initialized'.")
vrrpOperProtocol = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 14), Integer().subtype(subtypeSpec=SingleValueConstraint(2,1,3,4,)).subtype(namedValues=NamedValues(("ip", 1), ("bridge", 2), ("decnet", 3), ("other", 4), )).clone(1)).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperProtocol.setDescription("The particular protocol being controlled by this Virtual\nRouter.\n\nNew enumerations to this list can only be added via a new\nRFC on the standards track.")
vrrpOperRowStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 3, 1, 15), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpOperRowStatus.setDescription("The row status variable, used in accordance to installation\nand removal conventions for conceptual rows. The rowstatus of\na currently active row in the vrrpOperTable is constrained\nby the operational state of the corresponding virtual router.\nWhen `vrrpOperRowStatus' is set to active(1), no other\nobjects in the conceptual row, with the exception of\n`vrrpOperAdminState', can be modified. Prior to setting the\n`vrrpOperRowStatus' object from `active' to a different value,\nthe `vrrpOperAdminState' object must be set to `down' and the\n`vrrpOperState' object be transitioned to `initialize'.\n\nTo create a row in this table, a manager sets this object\nto either createAndGo(4) or createAndWait(5). Until instances\nof all corresponding columns are appropriately configured,\nthe value of the corresponding instance of the `vrrpOperRowStatus'\ncolumn will be read as notReady(3).\nIn particular, a newly created row cannot be made active(1)\nuntil (minimally) the corresponding instance of\n`vrrpOperVrId' has been set and there is at least one active\nrow in the `vrrpAssoIpAddrTable' defining an associated\nIP address for the virtual router.")
vrrpAssoIpAddrTable = MibTable((1, 3, 6, 1, 2, 1, 68, 1, 4))
if mibBuilder.loadTexts: vrrpAssoIpAddrTable.setDescription("The table of addresses associated with this virtual router.")
vrrpAssoIpAddrEntry = MibTableRow((1, 3, 6, 1, 2, 1, 68, 1, 4, 1)).setIndexNames((0, "IF-MIB", "ifIndex"), (0, "VRRP-MIB", "vrrpOperVrId"), (0, "VRRP-MIB", "vrrpAssoIpAddr"))
if mibBuilder.loadTexts: vrrpAssoIpAddrEntry.setDescription("An entry in the table contains an IP address that is\nassociated with a virtual router. The number of rows for\na given ifIndex and VrId will equal the number of IP\naddresses associated (e.g., backed up) by the virtual\nrouter (equivalent to 'vrrpOperIpAddrCount').\n\nRows in the table cannot be modified unless the value\nof `vrrpOperAdminState' is `disabled' and the\n`vrrpOperState' has transitioned to `initialize'.")
vrrpAssoIpAddr = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 4, 1, 1), IpAddress()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: vrrpAssoIpAddr.setDescription("The assigned IP addresses that a virtual router is\nresponsible for backing up.")
vrrpAssoIpAddrRowStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 1, 4, 1, 2), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: vrrpAssoIpAddrRowStatus.setDescription("The row status variable, used according to installation\nand removal conventions for conceptual rows. Setting this\nobject to active(1) or createAndGo(4) results in the\naddition of an associated address for a virtual router.\nDestroying the entry or setting it to notInService(2)\nremoves the associated address from the virtual router.\nThe use of other values is implementation-dependent.")
vrrpTrapPacketSrc = MibScalar((1, 3, 6, 1, 2, 1, 68, 1, 5), IpAddress()).setMaxAccess("notifyonly")
if mibBuilder.loadTexts: vrrpTrapPacketSrc.setDescription("The IP address of an inbound VRRP packet. Used by\nvrrpTrapAuthFailure trap.")
vrrpTrapAuthErrorType = MibScalar((1, 3, 6, 1, 2, 1, 68, 1, 6), Integer().subtype(subtypeSpec=SingleValueConstraint(1,3,2,)).subtype(namedValues=NamedValues(("invalidAuthType", 1), ("authTypeMismatch", 2), ("authFailure", 3), ))).setMaxAccess("notifyonly")
if mibBuilder.loadTexts: vrrpTrapAuthErrorType.setDescription("Potential types of configuration conflicts.\nUsed by vrrpAuthFailure trap.")
vrrpStatistics = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 2))
vrrpRouterChecksumErrors = MibScalar((1, 3, 6, 1, 2, 1, 68, 2, 1), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpRouterChecksumErrors.setDescription("The total number of VRRP packets received with an invalid\nVRRP checksum value.")
vrrpRouterVersionErrors = MibScalar((1, 3, 6, 1, 2, 1, 68, 2, 2), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpRouterVersionErrors.setDescription("The total number of VRRP packets received with an unknown\nor unsupported version number.")
vrrpRouterVrIdErrors = MibScalar((1, 3, 6, 1, 2, 1, 68, 2, 3), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpRouterVrIdErrors.setDescription("The total number of VRRP packets received with an invalid\nVRID for this virtual router.")
vrrpRouterStatsTable = MibTable((1, 3, 6, 1, 2, 1, 68, 2, 4))
if mibBuilder.loadTexts: vrrpRouterStatsTable.setDescription("Table of virtual router statistics.")
vrrpRouterStatsEntry = MibTableRow((1, 3, 6, 1, 2, 1, 68, 2, 4, 1))
if mibBuilder.loadTexts: vrrpRouterStatsEntry.setDescription("An entry in the table, containing statistics information\nabout a given virtual router.")
vrrpStatsBecomeMain = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 1), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsBecomeMain.setDescription("The total number of times that this virtual router's state\nhas transitioned to MASTER.")
vrrpStatsAdvertiseRcvd = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 2), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsAdvertiseRcvd.setDescription("The total number of VRRP advertisements received by this\nvirtual router.")
vrrpStatsAdvertiseIntervalErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 3), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsAdvertiseIntervalErrors.setDescription("The total number of VRRP advertisement packets received\nfor which the advertisement interval is different than the\none configured for the local virtual router.")
vrrpStatsAuthFailures = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsAuthFailures.setDescription("The total number of VRRP packets received that do not pass\nthe authentication check.")
vrrpStatsIpTtlErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsIpTtlErrors.setDescription("The total number of VRRP packets received by the virtual\nrouter with IP TTL (Time-To-Live) not equal to 255.")
vrrpStatsPriorityZeroPktsRcvd = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 6), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsPriorityZeroPktsRcvd.setDescription("The total number of VRRP packets received by the virtual\nrouter with a priority of '0'.")
vrrpStatsPriorityZeroPktsSent = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 7), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsPriorityZeroPktsSent.setDescription("The total number of VRRP packets sent by the virtual router\nwith a priority of '0'.")
vrrpStatsInvalidTypePktsRcvd = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 8), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsInvalidTypePktsRcvd.setDescription("The number of VRRP packets received by the virtual router\nwith an invalid value in the 'type' field.")
vrrpStatsAddressListErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 9), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsAddressListErrors.setDescription("The total number of packets received for which the address\nlist does not match the locally configured list for the\nvirtual router.")
vrrpStatsInvalidAuthType = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 10), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsInvalidAuthType.setDescription("The total number of packets received with an unknown\nauthentication type.")
vrrpStatsAuthTypeMismatch = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 11), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsAuthTypeMismatch.setDescription("The total number of packets received with 'Auth Type' not\nequal to the locally configured authentication method\n(`vrrpOperAuthType').")
vrrpStatsPacketLengthErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 68, 2, 4, 1, 12), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: vrrpStatsPacketLengthErrors.setDescription("The total number of packets received with a packet length\nless than the length of the VRRP header.")
vrrpConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 3))
vrrpMIBCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 3, 1))
vrrpMIBGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 68, 3, 2))

# Augmentions
vrrpOperEntry.registerAugmentions(("VRRP-MIB", "vrrpRouterStatsEntry"))
vrrpRouterStatsEntry.setIndexNames(*vrrpOperEntry.getIndexNames())

# Notifications

vrrpTrapNewMain = NotificationType((1, 3, 6, 1, 2, 1, 68, 0, 1)).setObjects(*(("VRRP-MIB", "vrrpOperMainIpAddr"), ) )
if mibBuilder.loadTexts: vrrpTrapNewMain.setDescription("The newMain trap indicates that the sending agent\nhas transitioned to 'Main' state.")
vrrpTrapAuthFailure = NotificationType((1, 3, 6, 1, 2, 1, 68, 0, 2)).setObjects(*(("VRRP-MIB", "vrrpTrapPacketSrc"), ("VRRP-MIB", "vrrpTrapAuthErrorType"), ) )
if mibBuilder.loadTexts: vrrpTrapAuthFailure.setDescription("A vrrpAuthFailure trap signifies that a packet has\nbeen received from a router whose authentication key\nor authentication type conflicts with this router's\nauthentication key or authentication type. Implementation\nof this trap is optional.")

# Groups

vrrpOperGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 68, 3, 2, 1)).setObjects(*(("VRRP-MIB", "vrrpAssoIpAddrRowStatus"), ("VRRP-MIB", "vrrpOperState"), ("VRRP-MIB", "vrrpOperAuthKey"), ("VRRP-MIB", "vrrpNodeVersion"), ("VRRP-MIB", "vrrpOperVirtualRouterUpTime"), ("VRRP-MIB", "vrrpNotificationCntl"), ("VRRP-MIB", "vrrpOperPreemptMode"), ("VRRP-MIB", "vrrpOperRowStatus"), ("VRRP-MIB", "vrrpOperAdminState"), ("VRRP-MIB", "vrrpOperIpAddrCount"), ("VRRP-MIB", "vrrpOperPrimaryIpAddr"), ("VRRP-MIB", "vrrpOperMainIpAddr"), ("VRRP-MIB", "vrrpOperAdvertisementInterval"), ("VRRP-MIB", "vrrpOperAuthType"), ("VRRP-MIB", "vrrpOperProtocol"), ("VRRP-MIB", "vrrpOperPriority"), ("VRRP-MIB", "vrrpOperVirtualMacAddr"), ) )
if mibBuilder.loadTexts: vrrpOperGroup.setDescription("Conformance group for VRRP operations.")
vrrpStatsGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 68, 3, 2, 2)).setObjects(*(("VRRP-MIB", "vrrpStatsAuthTypeMismatch"), ("VRRP-MIB", "vrrpStatsPriorityZeroPktsRcvd"), ("VRRP-MIB", "vrrpRouterVrIdErrors"), ("VRRP-MIB", "vrrpStatsAddressListErrors"), ("VRRP-MIB", "vrrpRouterChecksumErrors"), ("VRRP-MIB", "vrrpStatsPriorityZeroPktsSent"), ("VRRP-MIB", "vrrpStatsPacketLengthErrors"), ("VRRP-MIB", "vrrpStatsBecomeMain"), ("VRRP-MIB", "vrrpStatsAdvertiseIntervalErrors"), ("VRRP-MIB", "vrrpStatsAuthFailures"), ("VRRP-MIB", "vrrpStatsAdvertiseRcvd"), ("VRRP-MIB", "vrrpStatsInvalidTypePktsRcvd"), ("VRRP-MIB", "vrrpRouterVersionErrors"), ("VRRP-MIB", "vrrpStatsInvalidAuthType"), ("VRRP-MIB", "vrrpStatsIpTtlErrors"), ) )
if mibBuilder.loadTexts: vrrpStatsGroup.setDescription("Conformance group for VRRP statistics.")
vrrpTrapGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 68, 3, 2, 3)).setObjects(*(("VRRP-MIB", "vrrpTrapPacketSrc"), ("VRRP-MIB", "vrrpTrapAuthErrorType"), ) )
if mibBuilder.loadTexts: vrrpTrapGroup.setDescription("Conformance group for objects contained in VRRP notifications.")
vrrpNotificationGroup = NotificationGroup((1, 3, 6, 1, 2, 1, 68, 3, 2, 4)).setObjects(*(("VRRP-MIB", "vrrpTrapNewMain"), ("VRRP-MIB", "vrrpTrapAuthFailure"), ) )
if mibBuilder.loadTexts: vrrpNotificationGroup.setDescription("The VRRP MIB Notification Group.")

# Compliances

vrrpMIBCompliance = ModuleCompliance((1, 3, 6, 1, 2, 1, 68, 3, 1, 1)).setObjects(*(("VRRP-MIB", "vrrpStatsGroup"), ("VRRP-MIB", "vrrpOperGroup"), ) )
if mibBuilder.loadTexts: vrrpMIBCompliance.setDescription("The core compliance statement for all VRRP implementations.")

# Exports

# Module identity
mibBuilder.exportSymbols("VRRP-MIB", PYSNMP_MODULE_ID=vrrpMIB)

# Types
mibBuilder.exportSymbols("VRRP-MIB", VrId=VrId)

# Objects
mibBuilder.exportSymbols("VRRP-MIB", vrrpMIB=vrrpMIB, vrrpNotifications=vrrpNotifications, vrrpOperations=vrrpOperations, vrrpNodeVersion=vrrpNodeVersion, vrrpNotificationCntl=vrrpNotificationCntl, vrrpOperTable=vrrpOperTable, vrrpOperEntry=vrrpOperEntry, vrrpOperVrId=vrrpOperVrId, vrrpOperVirtualMacAddr=vrrpOperVirtualMacAddr, vrrpOperState=vrrpOperState, vrrpOperAdminState=vrrpOperAdminState, vrrpOperPriority=vrrpOperPriority, vrrpOperIpAddrCount=vrrpOperIpAddrCount, vrrpOperMainIpAddr=vrrpOperMainIpAddr, vrrpOperPrimaryIpAddr=vrrpOperPrimaryIpAddr, vrrpOperAuthType=vrrpOperAuthType, vrrpOperAuthKey=vrrpOperAuthKey, vrrpOperAdvertisementInterval=vrrpOperAdvertisementInterval, vrrpOperPreemptMode=vrrpOperPreemptMode, vrrpOperVirtualRouterUpTime=vrrpOperVirtualRouterUpTime, vrrpOperProtocol=vrrpOperProtocol, vrrpOperRowStatus=vrrpOperRowStatus, vrrpAssoIpAddrTable=vrrpAssoIpAddrTable, vrrpAssoIpAddrEntry=vrrpAssoIpAddrEntry, vrrpAssoIpAddr=vrrpAssoIpAddr, vrrpAssoIpAddrRowStatus=vrrpAssoIpAddrRowStatus, vrrpTrapPacketSrc=vrrpTrapPacketSrc, vrrpTrapAuthErrorType=vrrpTrapAuthErrorType, vrrpStatistics=vrrpStatistics, vrrpRouterChecksumErrors=vrrpRouterChecksumErrors, vrrpRouterVersionErrors=vrrpRouterVersionErrors, vrrpRouterVrIdErrors=vrrpRouterVrIdErrors, vrrpRouterStatsTable=vrrpRouterStatsTable, vrrpRouterStatsEntry=vrrpRouterStatsEntry, vrrpStatsBecomeMain=vrrpStatsBecomeMain, vrrpStatsAdvertiseRcvd=vrrpStatsAdvertiseRcvd, vrrpStatsAdvertiseIntervalErrors=vrrpStatsAdvertiseIntervalErrors, vrrpStatsAuthFailures=vrrpStatsAuthFailures, vrrpStatsIpTtlErrors=vrrpStatsIpTtlErrors, vrrpStatsPriorityZeroPktsRcvd=vrrpStatsPriorityZeroPktsRcvd, vrrpStatsPriorityZeroPktsSent=vrrpStatsPriorityZeroPktsSent, vrrpStatsInvalidTypePktsRcvd=vrrpStatsInvalidTypePktsRcvd, vrrpStatsAddressListErrors=vrrpStatsAddressListErrors, vrrpStatsInvalidAuthType=vrrpStatsInvalidAuthType, vrrpStatsAuthTypeMismatch=vrrpStatsAuthTypeMismatch, vrrpStatsPacketLengthErrors=vrrpStatsPacketLengthErrors, vrrpConformance=vrrpConformance, vrrpMIBCompliances=vrrpMIBCompliances, vrrpMIBGroups=vrrpMIBGroups)

# Notifications
mibBuilder.exportSymbols("VRRP-MIB", vrrpTrapNewMain=vrrpTrapNewMain, vrrpTrapAuthFailure=vrrpTrapAuthFailure)

# Groups
mibBuilder.exportSymbols("VRRP-MIB", vrrpOperGroup=vrrpOperGroup, vrrpStatsGroup=vrrpStatsGroup, vrrpTrapGroup=vrrpTrapGroup, vrrpNotificationGroup=vrrpNotificationGroup)

# Compliances
mibBuilder.exportSymbols("VRRP-MIB", vrrpMIBCompliance=vrrpMIBCompliance)
