# Lazy PXE Boot
#
# Copyright (c) 2020 Jason Miley
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# SPDX-License-Identifier: 0BSD

import socket
import struct
import sys
from collections import OrderedDict

class DHCP_Server:
  sock = None

  def __init__(self):
    pass

  def run(self):
    localIP = '192.168.2.2'
    router  = '192.168.2.1'
    subnetMask  = '255.255.255.0'
    domain = 'generic-net'
    tftpIP  = '192.168.2.2'
    # bootFilename = 'grub_x86_64.efi'
    bootFilename = 'BOOTX64.EFI'
    macFilter = ['00:07:32:61:DC:13']
    ipTmp = '192.168.2.3'

    print('Lazy PXE Boot')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((localIP, 67))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)

    try:
      while True:
        try:
          data, addr = sock.recvfrom(1472)
          print('-' * 75)

          request = DHCP_Message()
          status = request.unpack(data)
          if not status:
            print("ERROR: Failed to unpack DHCP message from %s:%d" % (addr[0], addr[1]))
            continue

          print("Got a DHCP message from %s:%d" % (addr[0], addr[1]))

          if request.messageType != DHCP_Constant.OP_CODE_BOOTREQUEST:
            print("WARNING: Got other traffic from %s:%d" % (addr[0], addr[1]))
            continue

          if DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE not in request.options:
            print("ERROR: Request from %s:%d lacks DHCP Message Type option" % (addr[0], addr[1]))
            continue

          macAddr = request.clientMAC.upper()
          if macAddr not in macFilter:
            print("WARNING: Got DHCP request from %s, but not serving that MAC address" % (macAddr))
            continue
          print("DHCP request from %s" % (macAddr))

          #
          msgType = request.options[DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE].value
          print("msgType = %d" % (msgType))
          if msgType == DHCP_Constant.MSG_TYPE_DHCPDISCOVER:
            response = DHCP_Message()
            response.messageType = DHCP_Constant.OP_CODE_BOOTREPLY
            response.hardwareType = request.hardwareType
            response.hardwareAddressLength = request.hardwareAddressLength
            response.hops = request.hops
            response.transactionID = request.transactionID
            response.secondsElapsed = request.secondsElapsed
            response.flags = request.flags
            response.clientIP = '0.0.0.0'
            response.yourIP = ipTmp
            response.nextServerIP = tftpIP
            response.relayAgentIP = '0.0.0.0'
            response.clientMAC = request.clientMAC
            response.serverHostname = ''
            response.bootFilename = bootFilename
            response.magicCookie = request.magicCookie
            #
            option = DHCP_Option()
            option.id = DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE
            option.data = struct.pack('>B', DHCP_Constant.MSG_TYPE_DHCPOFFER)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = DHCP_Constant.OPTION_SERVER_IDENTIFIER
            option.data = DHCP_Utility.ip_pack(localIP)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 51
            option.data = struct.pack('>L', 6657)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 1
            option.data = DHCP_Utility.ip_pack(subnetMask)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 3
            option.data = DHCP_Utility.ip_pack(router)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 6
            option.data = DHCP_Utility.ip_pack(router)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 15
            optionFormat = "%ss" % (len(domain))
            option.data = struct.pack(optionFormat, bytes(domain.encode('ascii')))
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 66
            optionFormat = "%ss" % (len(tftpIP))
            option.data = struct.pack(optionFormat, bytes(tftpIP.encode('ascii')))
            response.options[option.id] = option
            #
            dataResponse = response.pack()
            # print(dataResponse)
            if request.flags & DHCP_Constant.FLAG_BROADCAST:
              sock.sendto(dataResponse, ('255.255.255.255', 68))
            else:
              # TODO: I need an ARP entry to do this!
              sock.sendto(dataResponse, (ipTmp, 68))
          elif msgType == DHCP_Constant.MSG_TYPE_DHCPREQUEST:
            response = DHCP_Message()
            response.messageType = DHCP_Constant.OP_CODE_BOOTREPLY
            response.hardwareType = request.hardwareType
            response.hardwareAddressLength = request.hardwareAddressLength
            response.hops = request.hops
            response.transactionID = request.transactionID
            response.secondsElapsed = request.secondsElapsed
            response.flags = request.flags
            response.clientIP = '0.0.0.0'
            response.yourIP = ipTmp
            response.nextServerIP = tftpIP
            response.relayAgentIP = '0.0.0.0'
            response.clientMAC = request.clientMAC
            response.serverHostname = ''
            response.bootFilename = bootFilename
            response.magicCookie = request.magicCookie
            #
            option = DHCP_Option()
            option.id = DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE
            option.data = struct.pack('>B', DHCP_Constant.MSG_TYPE_DHCPACK)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = DHCP_Constant.OPTION_SERVER_IDENTIFIER
            option.data = DHCP_Utility.ip_pack(localIP)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 51
            option.data = struct.pack('>L', 6657)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 1
            option.data = DHCP_Utility.ip_pack(subnetMask)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 3
            option.data = DHCP_Utility.ip_pack(router)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 6
            option.data = DHCP_Utility.ip_pack(router)
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 15
            optionFormat = "%ss" % (len(domain))
            option.data = struct.pack(optionFormat, bytes(domain.encode('ascii')))
            response.options[option.id] = option
            #
            option = DHCP_Option()
            option.id = 66
            optionFormat = "%ss" % (len(tftpIP))
            option.data = struct.pack(optionFormat, bytes(tftpIP.encode('ascii')))
            response.options[option.id] = option
            #
            dataResponse = response.pack()
            # print(dataResponse)
            if request.flags & DHCP_Constant.FLAG_BROADCAST:
              sock.sendto(dataResponse, ('255.255.255.255', 68))
            else:
              # TODO: I need an ARP entry to do this!
              sock.sendto(dataResponse, (ipTmp, 68))

          #
          #
          #
          #
          #
        except socket.timeout:
          continue
    except KeyboardInterrupt as e:
      print('Ctrl-C')
      sys.exit(1)

    #

  #

# DHCP Constant
class DHCP_Constant:
  # Packet Op Codes
  OP_CODE_BOOTREQUEST = 1
  OP_CODE_BOOTREPLY   = 2

  # Hardware Address Types
  HTYPE_ETHERNET      = 1

  # Flags
  FLAG_BROADCAST      = 0x8000

  # Magic Cookie ("99.130.83.99")
  MAGIC_COOKIE_DHCP   = 0x63825363

  # Options
  OPTION_PAD                       = 0
  OPTION_REQUESTED_IP_ADDRESS      = 50
  OPTION_DHCP_MESSAGE_TYPE         = 53
  OPTION_SERVER_IDENTIFIER         = 54
  OPTION_PARAMETER_REQUEST_LIST    = 55
  OPTION_MESSAGE                   = 56
  OPTION_MAXIMUM_DHCP_MESSAGE_SIZE = 57
  # OPTION_
  OPTION_END                       = 255

  # DHCP Message Types
  MSG_TYPE_DHCPDISCOVER = 1
  MSG_TYPE_DHCPOFFER    = 2
  MSG_TYPE_DHCPREQUEST  = 3
  MSG_TYPE_DHCPDECLINE  = 4
  MSG_TYPE_DHCPACK      = 5
  MSG_TYPE_DHCPNAK      = 6
  MSG_TYPE_DHCPRELEASE  = 7
  MSG_TYPE_DHCPINFORM   = 8

# DHCP Message
class DHCP_Message:

  def __init__(self):
    self.data = bytes()
    self.messageType = None
    self.hardwareType = None
    self.hardwareAddressLength = 0
    self.hops = 0
    self.transactionID = 0
    self.secondsElapsed = 0
    self.flags = 0
    self.clientIP = '0.0.0.0'
    self.yourIP = '0.0.0.0'
    self.nextServerIP = '0.0.0.0'
    self.relayAgentIP = '0.0.0.0'
    self.clientMAC = '00:00:00:00:00:00'
    self.serverHostname = ''
    self.bootFilename = ''
    self.magicCookie = 0x00000000
    self.options = OrderedDict()

  # Unpack DHCP message
  def unpack(self, data, offset = 0):

    # TODO: Provide a sanity check where packet must be >= 300 bytes?

    # Message type
    try:
      format = '>B'
      self.messageType = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("messageType = %d" % (self.messageType))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack message type (offset %d)" % (offset))
      print(e)
      return 0

    # Hardware type
    try:
      format = '>B'
      self.hardwareType = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("hardwareType = %d" % (self.hardwareType))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack hardware type (offset %d)" % (offset))
      print(e)
      return 0

    # Hardware address length
    try:
      format = '>B'
      self.hardwareAddressLength = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("hardwareAddressLength = %d" % (self.hardwareAddressLength))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack hardware address length (offset %d)" % (offset))
      print(e)
      return 0

    # Verify the length matches an Ethernet MAC address
    if self.hardwareAddressLength != 6:
      print("ERROR: DHCP Message: Hardware address length does not match Ethernet MAC address length (received %d, expected 6)" % (self.hardwareAddressLength))
      return 0

    # Hops
    try:
      format = '>B'
      self.hops = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("hops = %d" % (self.hops))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack hops (offset %d)" % (offset))
      print(e)
      return 0

    # Transaction ID
    try:
      format = '>L'
      self.transactionID = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("transactionID = 0x%08X" % (self.transactionID))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack transaction ID (offset %d)" % (offset))
      print(e)
      return 0

    # Seconds elapsed
    try:
      format = '>H'
      self.secondsElapsed = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("secondsElapsed = %d" % (self.secondsElapsed))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack seconds elapsed (offset %d)" % (offset))
      print(e)
      return 0

    # Flags
    try:
      format = '>H'
      self.flags = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("flags = 0x%04X" % (self.flags))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack flags (offset %d)" % (offset))
      print(e)
      return 0

    # Client IP address
    try:
      (self.clientIP, offset) = DHCP_Utility.ip_unpack(data, offset)
      print("clientIP = %s" % (self.clientIP))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack client IP address (offset %d)" % (offset))
      print(e)
      return 0

    # Your IP address
    try:
      (self.yourIP, offset) = DHCP_Utility.ip_unpack(data, offset)
      print("yourIP = %s" % (self.yourIP))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack your IP address (offset %d)" % (offset))
      print(e)
      return 0

    # Next server IP address
    try:
      (self.nextServerIP, offset) = DHCP_Utility.ip_unpack(data, offset)
      print("nextServerIP = %s" % (self.nextServerIP))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack next server IP address (offset %d)" % (offset))
      print(e)
      return 0

    # Relay agent IP address
    try:
      (self.relayAgentIP, offset) = DHCP_Utility.ip_unpack(data, offset)
      print("relayAgentIP = %s" % (self.relayAgentIP))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack relay agent IP address (offset %d)" % (offset))
      print(e)
      return 0

    # Client MAC address
    offsetTmp = offset
    try:
      print("offset = %d" % (offset))
      (self.clientMAC, offset) = DHCP_Utility.mac_unpack(data, offset, self.hardwareAddressLength)
      print("clientMAC = %s" % (self.clientMAC))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack client MAC address (offset %d)" % (offset))
      print(e)
      return 0
    try:
      offsetDiff = 16 - (offset - offsetTmp)
      if offset > 0:
        format = '>'
        format += 'B' * offsetDiff
        clientMACPadding = struct.unpack_from(format, data, offset)
        offset += offsetDiff
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack client MAC address padding (offset %d)" % (offset))
      print(e)
      return 0


    # Server host name
    try:
      format = '64s'
      self.serverHostname = struct.unpack_from(format, data, offset)[0]
      self.serverHostname = self.serverHostname.split(b"\0", 1)[0].decode('ascii')
      offset += struct.calcsize(format)
      print("serverHostname = %s" % (self.serverHostname))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack server host name (offset %d)" % (offset))
      print(e)
      return 0

    # Boot file name
    try:
      format = '128s'
      self.bootFilename = struct.unpack_from(format, data, offset)[0]
      self.bootFilename = self.bootFilename.split(b"\0", 1)[0].decode('ascii')
      offset += struct.calcsize(format)
      print("bootFilename = %s" % (self.bootFilename))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack boot file name (offset %d)" % (offset))
      print(e)
      return 0

    # Magic Cookie
    try:
      format = '>L'
      self.magicCookie = struct.unpack_from(format, data, offset)[0]
      offset += struct.calcsize(format)
      print("magicCookie = 0x%08X" % (self.magicCookie))
    except struct.error as e:
      print("ERROR: DHCP Message: Failed to unpack magic cookie (offset %d)" % (offset))
      print(e)
      return 0

    # Verify the magic cookie
    if self.magicCookie != DHCP_Constant.MAGIC_COOKIE_DHCP:
      print("ERROR: DHCP Message: Magic cookie mismatch (received 0x%08X, expected 0x%08X)" % (self.magicCookie, DHCP_Constant.MAGIC_COOKIE_DHCP))
      return 0

    # TODO: REMOVE
    # print("data is length %d" % (len(data)))

    # Options
    while True:
      try:
        option = DHCP_Option()
        id, length, optionData, optionValue, offset = option.unpack(data, offset)
        if id == DHCP_Constant.OPTION_END:
          print("END!")
          break
        # else:
        #   print("id = %d, length = %d, optionData = %s ... offset = %d" % (id, length, optionData, offset))
        #   if id == DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE:
        #     print("  *** MESSAGE TYPE = %s" % (DHCP_Utility.msg_type_to_str(optionData)))
        #   # offset += delta
        self.options[id] = option
      except Exception as e:
        print("ERROR: DHCP Message: Failed to unpack option (offset %d)" % (offset))
        print(e)
        return 0

      #

    #
    # print("data length = %d" % (len(data)))

    return 1

  # Pack DHCP message
  def pack(self):
    self.data = bytes()

    # Message type
    format = '>B'
    self.data += struct.pack(format, self.messageType)

    # Hardware type
    format = '>B'
    self.data += struct.pack(format, self.hardwareType)

    # Hardware address length
    format = '>B'
    self.data += struct.pack(format, self.hardwareAddressLength)

    # Hops
    format = '>B'
    self.data += struct.pack(format, self.hops)

    # Transaction ID
    format = '>L'
    self.data += struct.pack(format, self.transactionID)

    # Seconds elapsed
    format = '>H'
    self.data += struct.pack(format, self.secondsElapsed)

    # Flags
    format = '>H'
    self.data += struct.pack(format, self.flags)

    # Client IP address
    self.data += DHCP_Utility.ip_pack(self.clientIP)

    # Your IP address
    self.data += DHCP_Utility.ip_pack(self.yourIP)

    # Next server IP address
    self.data += DHCP_Utility.ip_pack(self.nextServerIP)

    # Relay agent IP address
    self.data += DHCP_Utility.ip_pack(self.relayAgentIP)

    # Client MAC address
    dataMAC = DHCP_Utility.mac_pack(self.clientMAC)
    self.data += dataMAC
    numPad = 16 - len(dataMAC)
    if numPad > 0:
      format = '>'
      format += 'B' * numPad
      padding = [0] * numPad
      self.data += struct.pack(format, *padding)

    # Server host name
    format = '64s'
    self.data += struct.pack(format, self.serverHostname.encode('ascii'))

    # Boot file name
    format = '128s'
    self.data += struct.pack(format, self.bootFilename.encode('ascii'))

    # Magic Cookie
    format = '>L'
    self.data += struct.pack(format, DHCP_Constant.MAGIC_COOKIE_DHCP)

    # Options
    for option in self.options:
      self.data += self.options[option].pack()
    self.data += struct.pack('>B', DHCP_Constant.OPTION_END)

    # Padding
    numPad = 300 - len(self.data)
    if numPad > 0:
      self.data += struct.pack('>B', DHCP_Constant.OPTION_PAD) * numPad

    #

    return self.data


# DHCP Option
class DHCP_Option:

  def __init__(self):
    self.option = bytes()
    self.id     = None
    self.length = 0
    self.data   = bytes()
    self.value  = None

  # Unpack DHCP option
  def unpack(self, data, offset = 0):

    #
    try:
      self.id = struct.unpack_from('>B', data, offset)[0]
      offset += 1
    except struct.error as e:
      raise self.DHCPOptionException(offset, 'Failed to unpack option id', str(e))

    # Option End (255)
    if self.id == DHCP_Constant.OPTION_END:
      self.length = 0
      self.option = bytes()
      self.data = bytes()
      self.value = None
      return [self.id, self.length, self.data, self.value, offset]

    #
    else:
      try:
        self.length = struct.unpack_from('>B', data, offset)[0]
        offset += 1
        # print("... self.length = %d" % (self.length))
      except struct.error as e:
        raise self.DHCPOptionException(offset, 'Failed to unpack option length', str(e))
      # print("offset = %d" % (offset))
      # print("length = %d" % (self.length))
      # print("dataLength = %d" % (len(data)))

      # Verify the option data can by extracted given the length
      dataLength = len(data)
      if (dataLength - offset) < self.length:
        raise self.DHCPOptionException(offset, "Data buffer (length = %d) insufficient given the option length (%d) and offset (%d)" % (dataLength, self.length, offset))

      # Store the entire chunk of option data
      try:
        self.option = data[(offset - 2):(self.length + 2)]
      except Exception as e:
        raise self.DHCPOptionException(offset - 2, 'Failed to extract option', str(e))

      # Unpack Requested IP Address
      if self.id == DHCP_Constant.OPTION_REQUESTED_IP_ADDRESS:
        try:
          self.data = data[offset:(offset + self.length)]
          (self.value, discard) = DHCP_Utility.ip_unpack(data, offset)
        except Exception as e:
          raise self.DHCPOptionException(offset, 'Failed to unpack Requested IP Address option', str(e))

      # Unpack DHCP Message Type
      elif self.id == DHCP_Constant.OPTION_DHCP_MESSAGE_TYPE:
        try:
          self.data = data[offset:(offset + self.length)]
          self.value = struct.unpack_from('>B', data, offset)[0]
        except Exception as e:
          raise self.DHCPOptionException(offset, 'Failed to unpack DHCP Message Type option', str(e))

      # Unpack Server Identifier
      elif self.id == DHCP_Constant.OPTION_SERVER_IDENTIFIER:
        try:
          self.data = data[offset:(offset + self.length)]
          (self.value, discard) = DHCP_Utility.ip_unpack(data, offset)
        except Exception as e:
          raise self.DHCPOptionException(offset, 'Failed to unpack Server Identifier option', str(e))

      # Unpack Parameter Request List
      elif self.id == DHCP_Constant.OPTION_PARAMETER_REQUEST_LIST:
        try:
          self.data = data[offset:(offset + self.length)]
          format = '>'
          format += 'B' * self.length
          self.value = list(struct.unpack_from(format, data, offset))
        except Exception as e:
          raise self.DHCPOptionException(offset, 'Failed to unpack Parameter Request List option', str(e))

      # Unpack Maximum DHCP Message Size
      elif self.id == DHCP_Constant.OPTION_MAXIMUM_DHCP_MESSAGE_SIZE:
        try:
          self.data = data[offset:(offset + self.length)]
          self.value = struct.unpack_from('>H', data, offset)[0]
        except struct.error as e:
          raise self.DHCPOptionException(offset, 'Failed to unpack Maximum DHCP Message Size option', str(e))

      # Unpack all other options
      else:
        try:
          self.data = data[offset:(offset + self.length)]
          self.value = self.data
        except Exception as e:
          raise self.DHCPOptionException(offset, 'Failed to extract option data', str(e))
      offset += self.length

      return [self.id, self.length, self.data, self.value, offset]

  # Pack DHCP option
  def pack(self):
    self.length = len(self.data)
    self.option = struct.pack('>B', self.id)
    self.option += struct.pack('>B', self.length)
    self.option += self.data
    return self.option

  # Format and pack DHCP option
  def pack_format(self, id, *args):
    self.id = id
    self.data = struct.pack(*args)
    self.length = len(self.data)
    self.option = struct.pack('>B', self.id)
    self.option += struct.pack('>B', self.length)
    self.option += self.data
    return self.option

  # DHCP Option Exception Class
  class DHCPOptionException(Exception):

    def __init__(self, offset, message = 'Undefined error', additional = None):
      self.offset = offset
      self.message = message
      self.additional = additional
      super().__init__(self.message)

    def __str__(self):
      excMessage = "DHCPOptionException: %s at offset %d" % (self.message, self.offset)
      if self.additional:
        excMessage += "\n%s" % (self.additional)
      return excMessage

# DHCP Utilities
class DHCP_Utility:
  #
  @staticmethod
  def msg_type_to_str(msgType):
    if msgType == DHCP_Constant.MSG_TYPE_DHCPDISCOVER:
      return 'DHCP Discover'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPOFFER:
      return 'DHCP Offer'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPREQUEST:
      return 'DHCP Request'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPDECLINE:
      return 'DHCP Decline'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPACK:
      return 'DHCP ACK'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPNAK:
      return 'DHCP NAK'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPRELEASE:
      return 'DHCP Release'
    elif msgType == DHCP_Constant.MSG_TYPE_DHCPINFORM:
      return 'DHCP Inform'
    else:
      return 'Unknown'

  # Pack IP address
  @staticmethod
  def ip_pack(ip):
    octets = [int(octet) for octet in ip.split('.')]
    return struct.pack('>BBBB', *octets)

  # Unpack IP address
  @staticmethod
  def ip_unpack(data, offset = 0):
    octets = struct.unpack_from('>BBBB', data, offset)
    ip = '.'.join([("%d" % (octet)) for octet in octets])
    offset += 4
    return (ip, offset)

  # Pack MAC Address
  @staticmethod
  def mac_pack(mac, length = 6):
    octets = [int(octet, 16) for octet in mac.split(':')]
    return struct.pack('>BBBBBB', *octets)

  # Unpack MAC Address
  @staticmethod
  def mac_unpack(data, offset = 0, length = 6):
    format = '>'
    format += ('B' * length)
    octets = struct.unpack_from(format, data, offset)
    mac = ':'.join([("%02X" % (octet)) for octet in octets])
    offset += struct.calcsize(format)
    return (mac, offset)



if __name__ == '__main__':
  dhcpServer = DHCP_Server()
  dhcpServer.run()

# EOF
