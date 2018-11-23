# PySNMP SMI module. Autogenerated from smidump -f python MPLS-TC-STD-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:21 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( Bits, Integer32, Integer32, ModuleIdentity, MibIdentifier, TimeTicks, Unsigned32, transmission, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Integer32", "Integer32", "ModuleIdentity", "MibIdentifier", "TimeTicks", "Unsigned32", "transmission")
( TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention")

# Types

class MplsAtmVcIdentifier(TextualConvention, Integer32):
    displayHint = "d"
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(32,65535)
    
class MplsBitRate(TextualConvention, Unsigned32):
    displayHint = "d"
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsBurstSize(TextualConvention, Unsigned32):
    displayHint = "d"
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsExtendedTunnelId(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsLSPID(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ConstraintsUnion(ValueSizeConstraint(2,2),ValueSizeConstraint(6,6),)
    
class MplsLabel(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsLabelDistributionMethod(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,1,)
    namedValues = NamedValues(("downstreamOnDemand", 1), ("downstreamUnsolicited", 2), )
    
class MplsLdpIdentifier(TextualConvention, OctetString):
    displayHint = "1d.1d.1d.1d:2d"
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(6,6)
    fixedLength = 6
    
class MplsLdpLabelType(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1,2,3,)
    namedValues = NamedValues(("generic", 1), ("atm", 2), ("frameRelay", 3), )
    
class MplsLspType(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(3,2,1,4,)
    namedValues = NamedValues(("unknown", 1), ("terminatingLsp", 2), ("originatingLsp", 3), ("crossConnectingLsp", 4), )
    
class MplsLsrIdentifier(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(4,4)
    fixedLength = 4
    
class MplsOwner(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,6,4,5,1,3,7,)
    namedValues = NamedValues(("unknown", 1), ("other", 2), ("snmp", 3), ("ldp", 4), ("crldp", 5), ("rsvpTe", 6), ("policyAgent", 7), )
    
class MplsPathIndex(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(1,4294967295)
    
class MplsPathIndexOrZero(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsRetentionMode(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,1,)
    namedValues = NamedValues(("conservative", 1), ("liberal", 2), )
    
class MplsTunnelAffinity(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class MplsTunnelIndex(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,65535)
    
class MplsTunnelInstanceIndex(Unsigned32):
    subtypeSpec = Unsigned32.subtypeSpec+ValueRangeConstraint(0,4294967295)
    
class TeHopAddress(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,32)
    
class TeHopAddressAS(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(4,4)
    fixedLength = 4
    
class TeHopAddressType(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(3,1,0,2,5,4,)
    namedValues = NamedValues(("unknown", 0), ("ipv4", 1), ("ipv6", 2), ("asnumber", 3), ("unnum", 4), ("lspid", 5), )
    
class TeHopAddressUnnum(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(4,4)
    fixedLength = 4
    

# Objects

mplsStdMIB = MibIdentifier((1, 3, 6, 1, 2, 1, 10, 166))
mplsTCStdMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 10, 166, 1)).setRevisions(("2004-06-03 00:00",))
if mibBuilder.loadTexts: mplsTCStdMIB.setOrganization("IETF Multiprotocol Label Switching (MPLS) Working\nGroup.")
if mibBuilder.loadTexts: mplsTCStdMIB.setContactInfo("        Thomas D. Nadeau\n\n\n\nCisco Systems, Inc.\ntnadeau@cisco.com\n\nJoan Cucchiara\nMarconi Communications, Inc.\njcucchiara@mindspring.com\n\nCheenu Srinivasan\nBloomberg L.P.\ncheenu@bloomberg.net\n\nArun Viswanathan\nForce10 Networks, Inc.\narunv@force10networks.com\n\nHans Sjostrand\nipUnplugged\nhans@ipunplugged.com\n\nKireeti Kompella\nJuniper Networks\nkireeti@juniper.net\n\nEmail comments to the MPLS WG Mailing List at\nmpls@uu.net.")
if mibBuilder.loadTexts: mplsTCStdMIB.setDescription("Copyright (C) The Internet Society (2004). The\ninitial version of this MIB module was published\nin RFC 3811. For full legal notices see the RFC\nitself or see:\nhttp://www.ietf.org/copyrights/ianamib.html\n\nThis MIB module defines TEXTUAL-CONVENTIONs\nfor concepts used in Multiprotocol Label\nSwitching (MPLS) networks.")

# Augmentions

# Exports

# Module identity
mibBuilder.exportSymbols("MPLS-TC-STD-MIB", PYSNMP_MODULE_ID=mplsTCStdMIB)

# Types
mibBuilder.exportSymbols("MPLS-TC-STD-MIB", MplsAtmVcIdentifier=MplsAtmVcIdentifier, MplsBitRate=MplsBitRate, MplsBurstSize=MplsBurstSize, MplsExtendedTunnelId=MplsExtendedTunnelId, MplsLSPID=MplsLSPID, MplsLabel=MplsLabel, MplsLabelDistributionMethod=MplsLabelDistributionMethod, MplsLdpIdentifier=MplsLdpIdentifier, MplsLdpLabelType=MplsLdpLabelType, MplsLspType=MplsLspType, MplsLsrIdentifier=MplsLsrIdentifier, MplsOwner=MplsOwner, MplsPathIndex=MplsPathIndex, MplsPathIndexOrZero=MplsPathIndexOrZero, MplsRetentionMode=MplsRetentionMode, MplsTunnelAffinity=MplsTunnelAffinity, MplsTunnelIndex=MplsTunnelIndex, MplsTunnelInstanceIndex=MplsTunnelInstanceIndex, TeHopAddress=TeHopAddress, TeHopAddressAS=TeHopAddressAS, TeHopAddressType=TeHopAddressType, TeHopAddressUnnum=TeHopAddressUnnum)

# Objects
mibBuilder.exportSymbols("MPLS-TC-STD-MIB", mplsStdMIB=mplsStdMIB, mplsTCStdMIB=mplsTCStdMIB)

