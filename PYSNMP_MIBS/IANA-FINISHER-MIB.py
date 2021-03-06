# PySNMP SMI module. Autogenerated from smidump -f python IANA-FINISHER-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:05 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( Bits, Integer32, ModuleIdentity, MibIdentifier, TimeTicks, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Integer32", "ModuleIdentity", "MibIdentifier", "TimeTicks", "mib-2")
( TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention")

# Types

class FinAttributeTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(3,15,13,82,20,162,81,31,19,80,50,8,10,17,83,40,160,14,100,5,16,12,9,7,18,161,130,11,4,1,30,6,)
    namedValues = NamedValues(("other", 1), ("finReferenceEdge", 10), ("slittingType", 100), ("finAxisOffset", 11), ("finJogEdge", 12), ("finHeadLocation", 13), ("wrappingType", 130), ("finOperationRestrictions", 14), ("finNumberOfPositions", 15), ("namedConfiguration", 16), ("stackOutputType", 160), ("stackOffset", 161), ("stackRotation", 162), ("finMediaTypeRestriction", 17), ("finPrinterInputTraySupported", 18), ("finPreviousFinishingOperation", 19), ("finNextFinishingOperation", 20), ("deviceName", 3), ("stitchingType", 30), ("stitchingDirection", 31), ("deviceVendorName", 4), ("foldingType", 40), ("deviceModel", 5), ("bindingType", 50), ("deviceVersion", 6), ("deviceSerialNumber", 7), ("maximumSheets", 8), ("punchHoleType", 80), ("punchHoleSizeLongDim", 81), ("punchHoleSizeShortDim", 82), ("punchPattern", 83), ("finProcessOffsetUnits", 9), )
    
class FinBindingTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(6,11,10,7,9,2,8,5,1,4,)
    namedValues = NamedValues(("other", 1), ("comb", 10), ("padding", 11), ("unknown", 2), ("tape", 4), ("plastic", 5), ("velo", 6), ("perfect", 7), ("spiral", 8), ("adhesive", 9), )
    
class FinDeviceTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(10,8,11,15,2,18,6,17,7,9,16,5,1,13,4,12,14,3,)
    namedValues = NamedValues(("other", 1), ("slitter", 10), ("separationCutter", 11), ("imprinter", 12), ("wrapper", 13), ("bander", 14), ("makeEnvelope", 15), ("stacker", 16), ("sheetRotator", 17), ("inserter", 18), ("unknown", 2), ("stitcher", 3), ("folder", 4), ("binder", 5), ("trimmer", 6), ("dieCutter", 7), ("puncher", 8), ("perforater", 9), )
    
class FinEdgeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(4,5,6,3,)
    namedValues = NamedValues(("topEdge", 3), ("bottomEdge", 4), ("leftEdge", 5), ("rightEdge", 6), )
    
class FinFoldingTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(4,1,2,3,5,)
    namedValues = NamedValues(("other", 1), ("unknown", 2), ("zFold", 3), ("halfFold", 4), ("letterFold", 5), )
    
class FinPunchHoleTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1,5,2,6,7,3,4,)
    namedValues = NamedValues(("other", 1), ("unknown", 2), ("round", 3), ("oblong", 4), ("square", 5), ("rectangular", 6), ("star", 7), )
    
class FinPunchPatternTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(4,10,16,13,7,2,6,9,14,12,8,1,17,11,5,15,18,)
    namedValues = NamedValues(("other", 1), ("twoHoleMetric", 10), ("swedish4Hole", 11), ("twoHoleUSSide", 12), ("fiveHoleUS", 13), ("sevenHoleUS", 14), ("mixed7H4S", 15), ("norweg6Hole", 16), ("metric26Hole", 17), ("metric30Hole", 18), ("unknown", 2), ("twoHoleUSTop", 4), ("threeHoleUS", 5), ("twoHoleDIN", 6), ("fourHoleDIN", 7), ("twentyTwoHoleUS", 8), ("nineteenHoleUS", 9), )
    
class FinSlittingTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,4,1,5,)
    namedValues = NamedValues(("other", 1), ("unknown", 2), ("slitAndSeparate", 4), ("slitAndMerge", 5), )
    
class FinStackOutputTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1,6,2,4,5,)
    namedValues = NamedValues(("other", 1), ("unknown", 2), ("straight", 4), ("offset", 5), ("crissCross", 6), )
    
class FinStitchingAngleTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(4,2,5,3,)
    namedValues = NamedValues(("unknown", 2), ("horizontal", 3), ("vertical", 4), ("slanted", 5), )
    
class FinStitchingDirTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,3,4,)
    namedValues = NamedValues(("unknown", 2), ("topDown", 3), ("bottomUp", 4), )
    
class FinStitchingTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(4,8,9,6,5,10,2,1,7,)
    namedValues = NamedValues(("other", 1), ("stapleDual", 10), ("unknown", 2), ("stapleTopLeft", 4), ("stapleBottomLeft", 5), ("stapleTopRight", 6), ("stapleBottomRight", 7), ("saddleStitch", 8), ("edgeStitch", 9), )
    
class FinWrappingTypeTC(Integer):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(2,5,1,4,)
    namedValues = NamedValues(("other", 1), ("unknown", 2), ("shrinkWrap", 4), ("paperWrap", 5), )
    

# Objects

ianafinisherMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 110)).setRevisions(("2004-06-02 00:00",))
if mibBuilder.loadTexts: ianafinisherMIB.setOrganization("IANA")
if mibBuilder.loadTexts: ianafinisherMIB.setContactInfo("Internet Assigned Numbers Authority\n\nPostal: ICANN\n        4676 Admiralty Way, Suite 330\n        Marina del Rey, CA 90292\n\nTel:    +1 310 823 9358\nE-Mail: iana&iana.org")
if mibBuilder.loadTexts: ianafinisherMIB.setDescription("This MIB module defines a set of finishing-related\nTEXTUAL-CONVENTIONs for use in Finisher MIB (RFC 3806)\nand other MIBs which need to specify finishing\nmechanism details.\n\nAny additions or changes to the contents of this MIB\nmodule require either publication of an RFC, or\nDesignated Expert Review as defined in RFC 2434,\nGuidelines for Writing an IANA Considerations Section\nin RFCs.  The Designated Expert will be selected by\nthe IESG Area Director(s) of the Applications Area.\n\nCopyright (C) The Internet Society (2004). The\n\ninitial version of this MIB module was published\nin RFC 3806. For full legal notices see the RFC\nitself or see:\nhttp://www.ietf.org/copyrights/ianamib.html")

# Augmentions

# Exports

# Module identity
mibBuilder.exportSymbols("IANA-FINISHER-MIB", PYSNMP_MODULE_ID=ianafinisherMIB)

# Types
mibBuilder.exportSymbols("IANA-FINISHER-MIB", FinAttributeTypeTC=FinAttributeTypeTC, FinBindingTypeTC=FinBindingTypeTC, FinDeviceTypeTC=FinDeviceTypeTC, FinEdgeTC=FinEdgeTC, FinFoldingTypeTC=FinFoldingTypeTC, FinPunchHoleTypeTC=FinPunchHoleTypeTC, FinPunchPatternTC=FinPunchPatternTC, FinSlittingTypeTC=FinSlittingTypeTC, FinStackOutputTypeTC=FinStackOutputTypeTC, FinStitchingAngleTypeTC=FinStitchingAngleTypeTC, FinStitchingDirTypeTC=FinStitchingDirTypeTC, FinStitchingTypeTC=FinStitchingTypeTC, FinWrappingTypeTC=FinWrappingTypeTC)

# Objects
mibBuilder.exportSymbols("IANA-FINISHER-MIB", ianafinisherMIB=ianafinisherMIB)

