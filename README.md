# PacketFirewall
A firewall system to allow packets based on a set of rules.
1. The code checks if a packet with a given direction, protocol, Port and an IPaddress, pass throught the Firewall, whose rules are defined in the CSV file.

2. The code uses an Ordered Map data-structure to check if the packet can pass throught the firewall. The benefit of this is that the check will always take O(logn) even in the worst case, where n is the size of the input. 
Also, we are not using an array to statically reserve the space as the space required can be huge, Order of 256*256*256*256*65535*4.

3. I have tested my code using the CSV file. I have also checked all the corner cases, such as where the packet is invalid because of only a single difference in the combination of (direction, protocol, Port and an IPaddress)

4. The optimization that could be done on the code is to associate each input with a number and store the pair with the (beginning number, ending number) in a sorted manner.
Eg: If the input is: direction=inbound,protocol=tcp,port=5,Ipaddress=192.168.3.255-192.168.5.50, we can associate the number to (in binary) 11 0000000000000101 11000000 10101000 00000011 11111111
and 11 0000000000000101 11000000 10101000 00000101 00110010. We can store the starting and ending for each valid packet in a sorted order.
Eg: (23,35) , (39,45) , Now each valid combination of (direction, protocol, Port and an IPaddress) in a rule will translate to a number. We can check if the rule is present in O(logn) time, and if it is not present we can add it in O(logn) time.
This will be able to handle rules, spanning over the same combination of (direction, protocol, Port and an IPaddress) and also rules like 0.0.0.0 to 255.255.255.255, as this will only add a pair instead of all valid IP addresses in between.

5. I have used Redis cache, JSON, MySQL as a part of my work experience as a software developer with United Health Group. I would be interested in working with Data Team and Policy team at Illumio.
