class AP:
    # Variables of class
    __channel = None
    __BSSID = None
    __crypto = None
    __SSID = None

    # Constructor
    def __init__(self, channel, BSSID, crypto, SSID):
        self.__channel = channel
        self.__BSSID = BSSID
        self.__crypto = crypto
        self.__SSID = SSID
    
    # Function get channel
    def getChannel(self):
        return self.__channel

    # Function get BSSID
    def getBSSID(self):
        return self.__BSSID

    # Function get crypto
    def getCrypto(self):
        return self.__crypto
 
    # Function get SSID
    def getSSID(self):
        return self.__SSID

    
