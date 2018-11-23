# PySNMP SMI module. Autogenerated from smidump -f python ROHC-RTP-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:35 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( rohcChannelID, rohcContextCID, ) = mibBuilder.importSymbols("ROHC-MIB", "rohcChannelID", "rohcContextCID")
( ModuleCompliance, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "ObjectGroup")
( Bits, Counter32, Integer32, ModuleIdentity, MibIdentifier, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, Unsigned32, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Counter32", "Integer32", "ModuleIdentity", "MibIdentifier", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "Unsigned32", "mib-2")
( TruthValue, ) = mibBuilder.importSymbols("SNMPv2-TC", "TruthValue")

# Objects

rohcRtpMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 114)).setRevisions(("2004-06-03 00:00",))
if mibBuilder.loadTexts: rohcRtpMIB.setOrganization("IETF Robust Header Compression Working Group")
if mibBuilder.loadTexts: rohcRtpMIB.setContactInfo("WG charter:\nhttp://www.ietf.org/html.charters/rohc-charter.html\n\nMailing Lists:\nGeneral Discussion: rohc@ietf.org\nTo Subscribe: rohc-request@ietf.org\nIn Body: subscribe your_email_address\n\nEditor:\nJuergen Quittek\nNEC Europe Ltd.\nNetwork Laboratories\nKurfuersten-Anlage 36\n69221 Heidelberg\nGermany\nTel: +49 6221 90511-15\nEMail: quittek@netlab.nec.de")
if mibBuilder.loadTexts: rohcRtpMIB.setDescription("This MIB module defines a set of objects for monitoring\nand configuring RObust Header Compression (ROHC).\nThe objects are specific to ROHC RTP (profile 0x0001),\nROHC UDP (profile 0x0002), and ROHC ESP (profile 0x0003)\ndefined in RFC 3095 and for the ROHC LLA profile (profile\n0x0005) defined in RFC 3242.\n\nCopyright (C) The Internet Society (2004). The\ninitial version of this MIB module was published\nin RFC 3816. For full legal notices see the RFC\nitself or see:\nhttp://www.ietf.org/copyrights/ianamib.html")
rohcRtpObjects = MibIdentifier((1, 3, 6, 1, 2, 1, 114, 1))
rohcRtpContextTable = MibTable((1, 3, 6, 1, 2, 1, 114, 1, 1))
if mibBuilder.loadTexts: rohcRtpContextTable.setDescription("This table lists and describes RTP profile specific\nproperties of compressor contexts and decompressor\ncontexts.  It extends the rohcContextTable of the\nROHC-MIB module.")
rohcRtpContextEntry = MibTableRow((1, 3, 6, 1, 2, 1, 114, 1, 1, 1)).setIndexNames((0, "ROHC-MIB", "rohcChannelID"), (0, "ROHC-MIB", "rohcContextCID"))
if mibBuilder.loadTexts: rohcRtpContextEntry.setDescription("An entry describing a particular context.")
rohcRtpContextState = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 3), Integer().subtype(subtypeSpec=SingleValueConstraint(5,3,4,2,1,6,)).subtype(namedValues=NamedValues(("initAndRefresh", 1), ("firstOrder", 2), ("secondOrder", 3), ("noContext", 4), ("staticContext", 5), ("fullContext", 6), ))).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextState.setDescription("State of the context as defined in RFC 3095.  States\ninitAndRefresh(1), firstOrder(2), and secondOrder(3)\nare states of compressor contexts, states noContext(4),\nstaticContext(5) and fullContext(6) are states of\ndecompressor contexts.")
rohcRtpContextMode = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 4), Integer().subtype(subtypeSpec=SingleValueConstraint(3,1,2,)).subtype(namedValues=NamedValues(("unidirectional", 1), ("optimistic", 2), ("reliable", 3), ))).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextMode.setDescription("Mode of the context.")
rohcRtpContextAlwaysPad = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 5), TruthValue().clone('false')).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextAlwaysPad.setDescription("Boolean, only applicable to compressor contexts using the\n\n\nLLA profile.  If its value is true, the compressor must\npad every RHP packet with a minimum of one octet ROHC\npadding.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextLargePktsAllowed = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 6), TruthValue().clone('true')).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextLargePktsAllowed.setDescription("Boolean, only applicable to compressor contexts using the\nLLA profile.  It specifies how to handle packets that do\nnot fit any of the preferred packet sizes specified.  If\nits value is true, the compressor must deliver the larger\npacket as-is and must not use segmentation.  If it is set\nto false, the ROHC segmentation scheme must be used to\nsplit the packet into two or more segments, and each\nsegment must further be padded to fit one of the preferred\npacket sizes.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextVerifyPeriod = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 7), Unsigned32().clone(0)).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextVerifyPeriod.setDescription("This object is only applicable to compressor contexts\nusing the LLA profile.  It specifies the minimum frequency\nwith which a packet validating the context must be sent.\nThis tells the compressor that a packet containing a CRC\n\n\nfield must be sent at least once every N packets, where N\nis the value of the object.  A value of 0 indicates that\nperiodical verifications are disabled.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextSizesAllowed = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 8), Unsigned32().subtype(subtypeSpec=ValueRangeConstraint(1, 4294967295))).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextSizesAllowed.setDescription("The value of this object is only valid for decompressor\ncontexts, i.e., if rohcInstanceType of the corresponding\nrohcContextEntry has the value decompressor(2).  For\ncompressor contexts where rohcInstanceType has the value\ncompressor(1), this object MUST NOT be instantiated.\n\nThis object contains the number of different packet sizes\nthat may be used in the context.")
rohcRtpContextSizesUsed = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 9), Unsigned32().subtype(subtypeSpec=ValueRangeConstraint(1, 4294967295))).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextSizesUsed.setDescription("The value of this object is only valid for decompressor\ncontexts, i.e., if rohcInstanceType of the corresponding\nrohcContextEntry has the value decompressor(2).  For\ncompressor contexts where rohcInstanceType has the value\ncompressor(1), this object MUST NOT be instantiated.\n\nThis object contains the number of different packet sizes\nthat are used in the context.")
rohcRtpContextACKs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 10), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextACKs.setDescription("The number of all positive feedbacks (ACK) sent or\nreceived in this context, respectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.")
rohcRtpContextNACKs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 11), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextNACKs.setDescription("The number of all dynamic negative feedbacks (ACK) sent\nor received in this context, respectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.")
rohcRtpContextSNACKs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 12), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextSNACKs.setDescription("The number of all static negative feedbacks (ACK) sent\nor received in this context, respectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\n\n\n\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.")
rohcRtpContextNHPs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 13), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextNHPs.setDescription("This object is only applicable to contexts using the\nLLA profile.  It contains the number of all no-header\npackets (NHP) sent or received in this context,\nrespectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextCSPs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 14), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextCSPs.setDescription("This object is only applicable to contexts using the\nLLA profile.  It contains the number of all context\nsynchronization packets (CSP) sent or received in this\ncontext, respectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\n\n\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextCCPs = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 15), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextCCPs.setDescription("This object is only applicable to contexts using the\nLLA profile.  It contains the number of all context check\npackets (CCP) sent or received in this context,\nrespectively.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextPktsLostPhysical = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 16), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextPktsLostPhysical.setDescription("This object is only applicable to decompressor contexts\n\n\nusing the LLA profile.  It contains the number of physical\npacket losses on the link between compressor and\ndecompressor, that have been indicated to the decompressor.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpContextPktsLostPreLink = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 1, 1, 17), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpContextPktsLostPreLink.setDescription("This object is only applicable to decompressor contexts\nusing the LLA profile.  It contains the number of pre-link\npacket losses on the link between compressor and\ndecompressor, that have been indicated to the decompressor.\n\nDiscontinuities in the value of this counter can\noccur at re-initialization of the management\nsystem, and at other times as indicated by the\nvalue of ifCounterDiscontinuityTime.  For checking\nifCounterDiscontinuityTime, the interface index is\nrequired.  It can be determined by reading the\nrohcChannelTable of the ROHC-MIB.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpPacketSizeTable = MibTable((1, 3, 6, 1, 2, 1, 114, 1, 2))
if mibBuilder.loadTexts: rohcRtpPacketSizeTable.setDescription("This table lists all allowed, preferred, and used packet\nsizes per compressor context and channel.\n\nNote, that the sizes table represents implementation\nparameters that are suggested by RFC 3095 and/or RFC 3242,\nbut that are not mandatory.")
rohcRtpPacketSizeEntry = MibTableRow((1, 3, 6, 1, 2, 1, 114, 1, 2, 1)).setIndexNames((0, "ROHC-MIB", "rohcChannelID"), (0, "ROHC-MIB", "rohcContextCID"), (0, "ROHC-RTP-MIB", "rohcRtpPacketSize"))
if mibBuilder.loadTexts: rohcRtpPacketSizeEntry.setDescription("An entry of a particular packet size.")
rohcRtpPacketSize = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 2, 1, 3), Unsigned32().subtype(subtypeSpec=ValueRangeConstraint(1, 4294967295))).setMaxAccess("noaccess")
if mibBuilder.loadTexts: rohcRtpPacketSize.setDescription("A packet size used as index.")
rohcRtpPacketSizePreferred = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 2, 1, 4), TruthValue()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpPacketSizePreferred.setDescription("This object is only applicable to compressor contexts\nusing the LLA profile.  When retrieved, it will have\nthe value true(1) if the packet size is preferred.\nOtherwise, its value will be false(2).\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpPacketSizeUsed = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 2, 1, 5), TruthValue()).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpPacketSizeUsed.setDescription("This object is only applicable to compressor contexts\nusing the UDP, RTP, or ESP profile.  When retrieved,\nit will have the value true(1) if the packet size is\nused.  Otherwise, its value will be false(2).\n\nThe value of this object is only valid for UDP, RTP,\nand ESP profiles, i.e., if the corresponding rohcProfile\nhas a value of either 0x0001, 0x0002 or 0x0003.  If\nthe corresponding rohcProfile has a value other than\n0x0001, 0x0002 or 0x0003, then this object MUST NOT be\ninstantiated.")
rohcRtpPacketSizeRestrictedType = MibTableColumn((1, 3, 6, 1, 2, 1, 114, 1, 2, 1, 6), Integer().subtype(subtypeSpec=SingleValueConstraint(2,1,3,)).subtype(namedValues=NamedValues(("nhpOnly", 1), ("rhpOnly", 2), ("noRestrictions", 3), ))).setMaxAccess("readonly")
if mibBuilder.loadTexts: rohcRtpPacketSizeRestrictedType.setDescription("This object is only applicable to preferred packet\n\n\nsizes of compressor contexts using the LLA profile.\nWhen retrieved, it will indicate whether the packet\nsize is preferred for NHP only, for RHP only, or\nfor both of them.\n\nThe value of this object is only valid for LLA profiles,\ni.e., if the corresponding rohcProfile has a value of\n0x0005.  If the corresponding rohcProfile has a value\nother than 0x0005, then this object MUST NOT be\ninstantiated.")
rohcRtpConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 114, 2))
rohcRtpCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 114, 2, 1))
rohcRtpGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 114, 2, 2))

# Augmentions

# Groups

rohcRtpContextGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 114, 2, 2, 1)).setObjects(*(("ROHC-RTP-MIB", "rohcRtpContextVerifyPeriod"), ("ROHC-RTP-MIB", "rohcRtpContextLargePktsAllowed"), ("ROHC-RTP-MIB", "rohcRtpContextAlwaysPad"), ("ROHC-RTP-MIB", "rohcRtpContextMode"), ("ROHC-RTP-MIB", "rohcRtpContextState"), ) )
if mibBuilder.loadTexts: rohcRtpContextGroup.setDescription("A collection of objects providing information about\nROHC RTP compressors and decompressors.")
rohcRtpPacketSizesGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 114, 2, 2, 2)).setObjects(*(("ROHC-RTP-MIB", "rohcRtpContextSizesUsed"), ("ROHC-RTP-MIB", "rohcRtpPacketSizeRestrictedType"), ("ROHC-RTP-MIB", "rohcRtpPacketSizePreferred"), ("ROHC-RTP-MIB", "rohcRtpContextSizesAllowed"), ("ROHC-RTP-MIB", "rohcRtpPacketSizeUsed"), ) )
if mibBuilder.loadTexts: rohcRtpPacketSizesGroup.setDescription("A collection of objects providing information about\nallowed and used packet sizes at a ROHC RTP compressor.")
rohcRtpStatisticsGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 114, 2, 2, 3)).setObjects(*(("ROHC-RTP-MIB", "rohcRtpContextSNACKs"), ("ROHC-RTP-MIB", "rohcRtpContextCCPs"), ("ROHC-RTP-MIB", "rohcRtpContextNHPs"), ("ROHC-RTP-MIB", "rohcRtpContextPktsLostPreLink"), ("ROHC-RTP-MIB", "rohcRtpContextNACKs"), ("ROHC-RTP-MIB", "rohcRtpContextCSPs"), ("ROHC-RTP-MIB", "rohcRtpContextACKs"), ("ROHC-RTP-MIB", "rohcRtpContextPktsLostPhysical"), ) )
if mibBuilder.loadTexts: rohcRtpStatisticsGroup.setDescription("A collection of objects providing ROHC compressor and\ndecompressor statistics.")

# Compliances

rohcRtpCompliance = ModuleCompliance((1, 3, 6, 1, 2, 1, 114, 2, 1, 1)).setObjects(*(("ROHC-RTP-MIB", "rohcRtpStatisticsGroup"), ("ROHC-RTP-MIB", "rohcRtpPacketSizesGroup"), ("ROHC-RTP-MIB", "rohcRtpContextGroup"), ) )
if mibBuilder.loadTexts: rohcRtpCompliance.setDescription("The compliance statement for SNMP entities that implement\nthe ROHC-RTP-MIB.\n\nNote that compliance with this compliance\nstatement requires compliance with the\nrohcCompliance MODULE-COMPLIANCE statement of the\nROHC-MIB and with the ifCompliance3 MODULE-COMPLIANCE\nstatement of the IF-MIB (RFC2863).")

# Exports

# Module identity
mibBuilder.exportSymbols("ROHC-RTP-MIB", PYSNMP_MODULE_ID=rohcRtpMIB)

# Objects
mibBuilder.exportSymbols("ROHC-RTP-MIB", rohcRtpMIB=rohcRtpMIB, rohcRtpObjects=rohcRtpObjects, rohcRtpContextTable=rohcRtpContextTable, rohcRtpContextEntry=rohcRtpContextEntry, rohcRtpContextState=rohcRtpContextState, rohcRtpContextMode=rohcRtpContextMode, rohcRtpContextAlwaysPad=rohcRtpContextAlwaysPad, rohcRtpContextLargePktsAllowed=rohcRtpContextLargePktsAllowed, rohcRtpContextVerifyPeriod=rohcRtpContextVerifyPeriod, rohcRtpContextSizesAllowed=rohcRtpContextSizesAllowed, rohcRtpContextSizesUsed=rohcRtpContextSizesUsed, rohcRtpContextACKs=rohcRtpContextACKs, rohcRtpContextNACKs=rohcRtpContextNACKs, rohcRtpContextSNACKs=rohcRtpContextSNACKs, rohcRtpContextNHPs=rohcRtpContextNHPs, rohcRtpContextCSPs=rohcRtpContextCSPs, rohcRtpContextCCPs=rohcRtpContextCCPs, rohcRtpContextPktsLostPhysical=rohcRtpContextPktsLostPhysical, rohcRtpContextPktsLostPreLink=rohcRtpContextPktsLostPreLink, rohcRtpPacketSizeTable=rohcRtpPacketSizeTable, rohcRtpPacketSizeEntry=rohcRtpPacketSizeEntry, rohcRtpPacketSize=rohcRtpPacketSize, rohcRtpPacketSizePreferred=rohcRtpPacketSizePreferred, rohcRtpPacketSizeUsed=rohcRtpPacketSizeUsed, rohcRtpPacketSizeRestrictedType=rohcRtpPacketSizeRestrictedType, rohcRtpConformance=rohcRtpConformance, rohcRtpCompliances=rohcRtpCompliances, rohcRtpGroups=rohcRtpGroups)

# Groups
mibBuilder.exportSymbols("ROHC-RTP-MIB", rohcRtpContextGroup=rohcRtpContextGroup, rohcRtpPacketSizesGroup=rohcRtpPacketSizesGroup, rohcRtpStatisticsGroup=rohcRtpStatisticsGroup)

# Compliances
mibBuilder.exportSymbols("ROHC-RTP-MIB", rohcRtpCompliance=rohcRtpCompliance)
