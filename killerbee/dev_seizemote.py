# KillerBee Device Support for:
# SEIZEMOTE 16 channel sniffer
# 

import os
import time
import struct
import time
import urllib2
import re
from struct import unpack

from datetime import datetime, timedelta
from kbutils import KBCapabilities, makeFCS, isIpAddr, KBInterfaceError

class SEIZEMOTE:
    def __init__(self):
        '''
        Instantiates the KillerBee class for the SEIZEMOTE Sniffer.
        @return: None
        @rtype: None
        '''
        self._channel = None
        self.handle = None
        #self.dev = dev
        
        #load overlay??

        #self.__stream_open = False
        self.capabilities = KBCapabilities()
        self.__set_capabilities()
        
    def close(self):
        '''Actually close the receiving UDP socket.'''
        self.sniffer_off()  # turn sniffer off if it's currently running
        self.handle.close() # socket.close()
        self.handle = None

    def check_capability(self, capab):
        return self.capabilities.check(capab)
    def get_capabilities(self):
        return self.capabilities.getlist()
    def __set_capabilities(self):
        '''
        Sets the capability information appropriate for the client and firmware version.
        @rtype: None
        @return: None
        '''
        self.capabilities.setcapab(KBCapabilities.SNIFF, True)
        self.capabilities.setcapab(KBCapabilities.SETCHAN, True)
        self.capabilities.setcapab(KBCapabilities.FREQ_2400, True)
        #self.capabilities.setcapab(KBCapabilities.FREQ_900, True)
        return

    # KillerBee expects the driver to implement this function
    def get_dev_info(self):
	'''
        Returns device information in a list identifying the device.
        @rtype: List
        @return: List of 3 strings identifying device.
        '''
        return ["SEIZEMOTE", "SEIZEMOTE v1", ""]

    # KillerBee expects the driver to implement this function
    def sniffer_on(self, channel=None):
        '''
        Turns the sniffer on such that pnext() will start returning observed
        data.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.SNIFF)

        # Because the Sewio just toggles, we have to only hit the page 
        # if we need to go from off to on state.
        self.__sync_status()
        if self.__stream_open == False:
            if channel != None:
                self.set_channel(channel)
            
            if not self.__make_rest_call('status.cgi?p=2', fetch=False):
                raise KBInterfaceError("Error instructing sniffer to start capture.")

            #This makes sure the change actually happened
            self.__sync_status()
            if not self.__stream_open:
                raise KBInterfaceError("Sniffer did not turn on capture.")
                
    # KillerBee expects the driver to implement this function
    def sniffer_off(self):
        '''
        Turns the sniffer off.
        @rtype: None
        '''
        # Because the Sewio just toggles, we have to only hit the page 
        # if we need to go from on to off state.
        self.__sync_status()
        if self.__stream_open == True:
            if not self.__make_rest_call('status.cgi?p=2', fetch=False):
                raise KBInterfaceError("Error instructing sniffer to stop capture.")
            
            #This makes sure the change actually happened
            self.__sync_status()
            if self.__stream_open:
                raise KBInterfaceError("Sniffer did not turn off capture.")
    
    # KillerBee expects the driver to implement this function
    def set_channel(self, channel):
        '''
        Sets the radio interface to the specified channel, and the matching modulation setting.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.SETCHAN)

        if self.capabilities.is_valid_channel(channel):
            # We only need to update our channel if it doesn't match the currently reported one.
            curChannel = self.__sniffer_channel()
            if channel != curChannel:
                self.modulation = self.__get_default_modulation(channel)
                print("Setting to channel {0}, modulation {1}.".format(channel, self.modulation))
                # Examples captured in fw v0.5 sniffing:
                #   channel 6, 250 compliant: http://10.10.10.2/settings.cgi?chn=6&modul=c&rxsens=0
                #   channel 12, 250 compliant: http://10.10.10.2/settings.cgi?chn=12&modul=0&rxsens=0
                #   chinese 0, 780 MHz, 250 compliant: http://10.10.10.2/settings.cgi?chn=128&modul=1c&rxsens=0
                #   chinese 3, 786 MHz, 250 compliant: http://10.10.10.2/settings.cgi?chn=131&modul=1c&rxsens=0
                #rxsens 0 is normal, 3 is high sensitivity to receive at
                self.__make_rest_call("settings.cgi?chn={0}&modul={1}&rxsens=3".format(channel, self.modulation), fetch=False)
                self._channel = self.__sniffer_channel()
            else:
                self._channel = curChannel
        else:
            raise Exception('Invalid channel number ({0}) was provided'.format(channel))

    # KillerBee expects the driver to implement this function
    def inject(self, packet, channel=None, count=1, delay=0):
        '''
        Not implemented.
        '''
        self.capabilities.require(KBCapabilities.INJECT)


    # KillerBee expects the driver to implement this function
    def pnext(self, timeout=100):
        '''
        Returns a dictionary containing packet data, else None.
        @type timeout: Integer
        @param timeout: Timeout to wait for packet reception in usec
        @rtype: List
        @return: Returns None is timeout expires and no packet received.  When a packet is received, a dictionary is returned with the keys bytes (string of packet bytes), validcrc (boolean if a vaid CRC), rssi (unscaled RSSI), and location (may be set to None). For backwards compatibility, keys for 0,1,2 are provided such that it can be treated as if a list is returned, in the form [ String: packet contents | Bool: Valid CRC | Int: Unscaled RSSI ]
        '''
        if self.__stream_open == False:
            self.sniffer_on() #start sniffing

        # Use socket timeouts to implement the timeout
        self.handle.settimeout(timeout / 1000000.0) # it takes seconds

        frame = None
        donetime = datetime.utcnow() + timedelta(microseconds=timeout)
        while True:
            try:
                data, addr = self.handle.recvfrom(1024)
            except error_timeout:
                return None
            # Ensure it's data coming from the right place, for now we just
            #  check the sending IP address. Ex: addr = ('10.10.10.2', 17754)
            if addr[0] != self.dev:
                continue
            # Dissect the UDP packet
            (frame, ch, validcrc, rssi, lqival, recdtime) = self.__parse_zep_v2(data)
            print "Valid CRC", validcrc, "LQI", lqival, "RSSI", rssi
            if frame == None or (ch is not None and ch != self._channel):
                #TODO this maybe should be an error condition, instead of ignored?
                print("ZEP parsing issue (bytes length={0}, channel={1}).".format(len(frame) if frame is not None else None, ch))
                continue
            break

        if frame is None:
            return None

        #Return in a nicer dictionary format, so we don't have to reference by number indicies.
        #Note that 0,1,2 indicies inserted twice for backwards compatibility.
        result = {0:frame, 1:validcrc, 2:rssi, 'bytes':frame, 'validcrc':validcrc, 'rssi':rssi, 'dbm':None, 'location':None, 'datetime':recdtime}
        if rssi is not None:
            # Per note from Sewino team regarding encoding of RSSI value as 2's complement dBm values
            if rssi > 127:  result['dbm'] = rssi - 256
            else:           result['dbm'] = rssi
        return result

    def jammer_on(self, channel=None):
        '''
        Not yet implemented.
        @type channel: Integer
        @param channel: Sets the channel, optional
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.PHYJAM)

    def jammer_off(self, channel=None):
        '''
        Not yet implemented.
        @return: None
        @rtype: None
        '''
        self.capabilities.require(KBCapabilities.PHYJAM)

