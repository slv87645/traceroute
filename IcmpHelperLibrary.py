# Steven Vu
# 2/11/2024
# Traceroute Assignment


# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #





    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 250                     # Time to live
        __rtt = 0
        __packetReceived = False
        __icmpErrorResults = {0: {"type": "Echo Reply",
                                  0: "No Code"},
                              3: {"type": "Destination Unreachable",
                                  0: "Net Unreachable",
                                  1: "Host Unreachable",
                                  2: "Protocol Unreachable",
                                  3: "Port Unreachable",
                                  4: "Fragmentation Needed and Don't Fragment was Set",
                                  5: "Source Route Failed",
                                  6: "Destination Network Unknown",
                                  7: "Destination Host Unknown",
                                  8: "Source Host Unknown",
                                  9: "Communication with Destination Network is Adminstratively Prohibited",
                                  10: "Communication with Destination Host is Adminstratively Prohibited",
                                  11: "Destination Network Unreachable for Type of Service",
                                  12: "Destiantion Host Unreachable for Type of Service",
                                  13: "Communication Administratively Prohibited",
                                  14: "Host Precedence Violation",
                                  15: "Precedence cutoff in effect"},
                              11: {"type": "Time Exceeded",
                                   0: "Time to Live exceeded in Transit",
                                   1: "Fragment Reassembly Time Exceeded"}}

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getRtt(self):
            return self.__rtt
        
        def getPacketReceived(self):
            return self.__packetReceived

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setRtt(self, rtt):
            self.__rtt = rtt

        def setPacketReceived(self, boolean):
            self.__packetReceived = boolean
        
        def getIcmpErrorResults(self, icmptype, type_or_icmpcode):
            return self.__icmpErrorResults[icmptype][type_or_icmpcode]

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm (looks like the link doesn't work any more so check below) 
            # https://web.archive.org/web/20220414173629/http://www.networksorcery.com/
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data is up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            packetSequenceNumber = self.getPacketSequenceNumber()
            icmpSequenceNumber = icmpReplyPacket.getIcmpSequenceNumber()
            packetIdentifier = self.getPacketIdentifier()
            icmpIdentifier = icmpReplyPacket.getIcmpIdentifier()
            packetDataRaw = self.getDataRaw()
            icmpDataRaw = icmpReplyPacket.getIcmpData()

            if packetSequenceNumber == icmpSequenceNumber:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)

            if packetIdentifier == icmpIdentifier:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)

            if packetDataRaw == icmpDataRaw:
                icmpReplyPacket.setIcmpDataRaw_isValid(True)

            print(f"Valid Echo Packet Sequence Number: {icmpReplyPacket.isValidSequenceNumber()} Expected: {packetSequenceNumber}  Actual: {icmpSequenceNumber}") if self.__DEBUG_IcmpPacket else 0
            print(f"Valid Echo Packet Identifier: {icmpReplyPacket.isValidIdentifier()}      Expected: {packetIdentifier}  Actual: {icmpIdentifier}") if self.__DEBUG_IcmpPacket else 0
            print(f"Valid Echo Packet Data Raw: {icmpReplyPacket.isValidDataRaw()}        Expected: {packetDataRaw}  Actual: {icmpDataRaw}") if self.__DEBUG_IcmpPacket else 0

            if icmpReplyPacket.isValidSequenceNumber() and icmpReplyPacket.isValidIdentifier() and icmpReplyPacket.isValidDataRaw():
                icmpReplyPacket.setIsValidResponse(True)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            print("\n")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    self.setPacketReceived(False)
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    self.setPacketReceived(False)                    
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        self.setPacketReceived(False)
                        print("  TTL=%d    RTT=%.0f ms    Type=%d:%s    Code=%d:%s    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    self.getIcmpErrorResults(icmpType, "type"),
                                    icmpCode,
                                    self.getIcmpErrorResults(icmpType, icmpCode),
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:                         # Destination Unreachable
                        self.setPacketReceived(False)
                        print("  TTL=%d    RTT=%.0f ms    Type=%d:%s    Code=%d:%s   %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      self.getIcmpErrorResults(icmpType, "type"),
                                      icmpCode,
                                      self.getIcmpErrorResults(icmpType, icmpCode),
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        self.setPacketReceived(True)
                        bytes = struct.calcsize("d") # new
                        timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0] # new
                        rtt = (timeReceived - timeSent) * 1000 # new
                        self.setRtt(rtt)

                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr, self.getPacketSequenceNumber, self.getPacketIdentifier, self.getDataRaw)
                        return      # Echo reply is the end and therefore should return

                    else:
                        self.setPacketReceived(False)
                        print("error")
            except timeout:
                self.setPacketReceived(False)
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __isValidSequenceNumber = False
        __isValidIdentifier = False
        __isValidDataRaw = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')
        
        def isValidSequenceNumber(self):
            return self.__isValidSequenceNumber

        def isValidIdentifier(self):
            return self.__isValidIdentifier

        def isValidDataRaw(self):
            return self.__isValidDataRaw

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__isValidSequenceNumber = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__isValidIdentifier = booleanValue

        def setIcmpDataRaw_isValid(self, booleanValue):
            self.__isValidDataRaw = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, expectedSequence, expectedIdentifier, expectedData):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            if not self.isValidResponse():
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Expected Identifier =%d Echo Identifier=%d    Expected Sequence Number = %d Echo Sequence Number=%d    Expected Data %s Echo Data=%s Valid=%s    %s" %
                    (
                        ttl,
                        (timeReceived - timeSent) * 1000,
                        self.getIcmpType(),
                        self.getIcmpCode(),
                        expectedIdentifier,
                        self.getIcmpIdentifier(),
                        expectedSequence,
                        self.getIcmpSequenceNumber(),
                        expectedData,
                        self.getIcmpData,
                        self.isValidResponse(),
                        addr[0]
                    )
                    )
                
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    Valid=%s    %s" %
                (
                    ttl,
                    (timeReceived - timeSent) * 1000,
                    self.getIcmpType(),
                    self.getIcmpCode(),
                    self.getIcmpIdentifier(),
                    self.getIcmpSequenceNumber(),
                    self.isValidResponse(),
                    addr[0]
                )
                )

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        rttList = []
        packetsLost = 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i
            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()
                                                            # Build IP
            if not icmpPacket.getPacketReceived():
                packetsLost += 1

            if icmpPacket.getRtt() > 0:
                rttList.append(icmpPacket.getRtt())

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        minRTT = min(rttList) if (len(rttList) > 1) else 0
        maxRTT = max(rttList) if (len(rttList) > 1) else 0
        avgRTT = 0
        for val in rttList:
            avgRTT += val
        if (len(rttList) > 1):
            avgRTT /= len(rttList)
        lostRate = (packetsLost / 4) * 100
        print(f"\nPackets Sent: 4  Packets Received: {4 - packetsLost} Packet Lost: {lostRate}% ")
        print("round-trip min/max/avg = %.0f/%.0f/%.0f ms" % (minRTT, maxRTT, avgRTT))

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for ttl in range(1, 31):
            print(f"Tracing route to {host} over a maximum of {ttl} hops")
            rttList = []
            packetsLost = 0

            for i in range(3):
                # Build packet
                icmpPacket = IcmpHelperLibrary.IcmpPacket()

                randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                            # Some PIDs are larger than 16 bit

                packetIdentifier = randomIdentifier
                packetSequenceNumber = i
                icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
                icmpPacket.setIcmpTarget(host)
                icmpPacket.setTtl(ttl)  # Set TTL for the packet
                icmpPacket.sendEchoRequest()
                                                                # Build IP
                if not icmpPacket.getPacketReceived():
                    packetsLost += 1

                if icmpPacket.getRtt() > 0:
                    rttList.append(icmpPacket.getRtt())

                icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                # we should be confirming values are correct, such as identifier and sequence number and data

            minRTT = min(rttList) if (len(rttList) > 1) else 0
            maxRTT = max(rttList) if (len(rttList) > 1) else 0
            avgRTT = 0
            for val in rttList:
                avgRTT += val
            if (len(rttList) > 1):
                avgRTT /= len(rttList)
            lostRate = (packetsLost / 3) * 100
            print(f"\nPackets Sent: 3  Packets Received: {3 - packetsLost} Packet Lost: {lostRate}% ")
            print("round-trip min/max/avg = %.0f/%.0f/%.0f ms" % (minRTT, maxRTT, avgRTT))        

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("www.google.com")
    # icmpHelperPing.traceRoute("www.alibaba.com")
    # icmpHelperPing.traceRoute("www.reddit.com")
    # icmpHelperPing.traceRoute("www.eurosport.fr")


if __name__ == "__main__":
    main()
