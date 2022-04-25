optional_arguments: []

# THIS YML-FILE HAS TO BE PLACE IN ROOT DIR OF THE USB FLASH.

# Description:
# The mobile_extension assembles the system call variables for the sniff_receiver,
# the optional arguments and the save statement to the entire CMD command,
# as if the user would start the sniff_receiver.py from the terminal.
# Only the optional_arguments have to be configured in this config file in a list of string format.

# BSP1:"-r -55 -m 12:34:56:78:9A:BC" 				        -> optional_arguments: ["-r","-55","-m","12:34:56:78:9A:BC"]
# BSP2: "-le -c 38" 						                -> optional_arguments: ["-le","-c","38"]
# BSP3: "-i 4E0BEA5355866BE38EF0AC2E3F0EBC22 -Q 6:6,39:6" 	-> optional_arguments: ["-i","4E0BEA5355866BE38EF0AC2E3F0EBC22","-Q","6:6,39:6"]
# BSP4: -no arguments-							            -> optional_arguments:[]

# supports optional arguments according to the development state of Sniffle:
#  -c {37,38,39}, --advchan {37,38,39} 	Advertising channel to listen on
#  -r RSSI, --rssi RSSI  		        Filter packets by minimum RSSI
#  -m MAC, --mac MAC     		        Filter packets by advertiser MAC
#  -i IRK, --irk IRK     		        Filter packets by advertiser IRK
#  -a, --advonly        	 	        Sniff only advertisements, don't follow connections
#  -e, --extadv          		        Capture BT5 extended (auxiliary) advertising
#  -H, --hop             		        Hop primary advertising channels in extended mode
#  -l, --longrange       		        Use long range (coded) PHY for primary advertising
#  -q, --quiet           		        Don't display empty packets
#  -Q PRELOAD, --preload PRELOAD	    Preload expected encrypted connection parameter changes
#  -n, --nophychange     		        Ignore encrypted PHY mode changes

# Not supported optional arguments in this config file:
#  -p, --pause           		        Pause sniffer after disconnect
#  -h, --help            		        show this help message and exit
#  -s SERPORT, --serport SERPORT	    Sniffer serial port name 	(Done automatically by mobile_extension)
#  -o OUTPUT, --output OUTPUT 		    PCAP output file name 		(Done automatically by mobile_extension)
