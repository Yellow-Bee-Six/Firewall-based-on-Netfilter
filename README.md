# Firewall-based-on-Netfilter
This is a simple firewall based on Netfilter
To install it into your linux system, run:

  make
  
  sudo make install
  
  sudo ./start.o
  
To uninstall it from your system, run:

  sudo make uninstall

Note:

  Once it has been installed, all the packets will be filtered, run:
  
    allow-all
    
  to allow all the packets
  
You can run input "help" to see more details.
