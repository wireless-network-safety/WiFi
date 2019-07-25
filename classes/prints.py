class PRINTS:
    # Colours for print
    __GREEN = '\033[92m'
    __RED = '\033[91m'
    __ENDC = '\033[0m'
    __BOLD = '\033[1m'

    #constructor
    def __init__(self):
        pass

    # Print our logo
    def logo(self):
        OurLogo = ""
        for row in range(7):
	    i = 7 - row
            # Printing Stars '*' in Right Angle Triangle Shape
	    for j in range(0, i):
	        OurLogo = OurLogo + "*"
	    for j in range(0, 7-i):
	        OurLogo = OurLogo + " "
	    OurLogo = OurLogo + "  "
	    # Printing Stars '*' in A Shape		
	    for col in range(5):
	        if(col == 0 or col == 4) or ((row == 0 or row == 3) and (col > 0 and col < 4)):
	            OurLogo = OurLogo + "*"
	        else:
		    OurLogo = OurLogo + " "
	    OurLogo = OurLogo + "  "
	    # Printing Stars '*' in S Shape		
	    for col in range(5):
	        if((row == 0 or row == 3 or row == 6) and (col > 0 and col < 4)) or ((row == 1 or row == 2) and (col == 0)) or ((row == 4 or row == 5) and (col == 4)):
	            OurLogo = OurLogo + "*"
	        else:
		    OurLogo = OurLogo + " "
	    OurLogo = OurLogo + "  "
	    # Printing Stars '*' in H Shape
	    for col in range(5):
	        if(col == 0 or col == 3) or (row == 3 and (col > 0 and col < 4)):
	            OurLogo = OurLogo + "*"
	        else:
		    OurLogo = OurLogo + " "
	    OurLogo = OurLogo + "  "
	    # Printing Stars '*' in Left Angle Triangle Shape
	    for j in range(0, 7-i):
	        OurLogo = OurLogo + " "
 	    for j in range(0, i):
	        OurLogo = OurLogo + "*"
	    OurLogo = OurLogo + "\n"
        print(self.__BOLD + OurLogo + self.__ENDC)

    # Print banner with info
    def banner(self):
        print(self.__BOLD + "\n+--------------------------------------------------------------------------------------------+" + self.__ENDC)
        print(self.__BOLD + "|NetSav v4.3                                                                                 |" + self.__ENDC)
        print(self.__BOLD + "|Coded by Alexey, Hodaya & Shir                                                              |" + self.__ENDC)
        print(self.__BOLD + "+--------------------------------------------------------------------------------------------+\n" + self.__ENDC)
    
    # Print logo of end code
    def fin(self):
        print(self.__BOLD + "\n\x1b[1;35m                             " + self.__ENDC)
        print(self.__BOLD + "    _    (^)                             " + self.__ENDC)
        print(self.__BOLD + "   (_\   |_|                             " + self.__ENDC)
        print(self.__BOLD + "    \_\  |_|                             " + self.__ENDC)
        print(self.__BOLD + "    _\_\,/_|                             " + self.__ENDC)
        print(self.__BOLD + "   (`\(_|`\|                             " + self.__ENDC)
        print(self.__BOLD + "  (`\,)  \ \'                            " + self.__ENDC)
        print(self.__BOLD + "   \,)   | |                             " + self.__ENDC)
        print(self.__BOLD + "     \__(__|\x1b[0m                      " + self.__ENDC)
        print(self.__BOLD + "                                         " + self.__ENDC)
        print(self.__BOLD + "\x1b[1;35m        Peace brothers and sisters!       " + self.__ENDC)
        print(self.__BOLD + "\n                                       " + self.__ENDC) 

