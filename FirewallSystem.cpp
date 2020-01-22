#include<bits/stdc++.h>
using namespace std;
class Firewall
{
	string path;// Stores the path of the file
	map<pair<bool,pair<bool,pair<int,pair<int,pair<int,pair<int,int> > > > > >,bool> mp; // Ordered HashMap data structure for (direction,protocol,port,ip-address) -> allowedOrNot (bool)
	map<string,bool> protocols; // Map string protocol to bool
	map<string,bool> directions;// Map string direction to bool
	
	void addFirewall() //Method to update the Ordered HashMap data structure according to the given rules
	{
		protocols["tcp"]=true;
		protocols["udp"]=false;
		directions["inbound"]=true;
		directions["outbound"]=false;
	  
	    //Attach the existing csv file to inout stream
	    ifstream file(path.c_str());
	 
		string line = "";
		vector<vector<string> > rules;
		vector<string> row;
		string word;
		// Iterate through each line and split the content using delimeter , and store each line in rules as a vector of string
		while (getline(file, line))
		{
			row.clear();
			std::vector<std::string> vec;
			stringstream s(line);  
	        while (getline(s, word, ',')) {  
	            row.push_back(word); 
	        } 
			rules.push_back(row);
		}
		
		// Close the File
		file.close();
		
		int numRules=rules.size();
		for(int i=1;i<numRules;i++) // Starting from 1, as 0th one is the header description
		{
			vector<string> cur_rule=rules[i]; // Current rule
			bool dir=directions[cur_rule[0]];
			bool protocol=protocols[cur_rule[1]];
			
			stringstream s1(cur_rule[2]);
			vector<int> ports; // For a range of port, stores the beginning and the ending port, In case of a single port, stores only the particular port number
			string temp;
			while(getline(s1,temp,'-'))
			{
				stringstream str_int(temp);
				int val;
				str_int>>val;
				ports.push_back(val);
			}
			
			vector<string> ipaddresses;// For a range of IPaddresses, stores the beginning and the ending IPaddress, In case of a single IPaddress, stores only the particular IPaddress
			stringstream s2(cur_rule[3]);
			while(getline(s2,temp,'-'))
			{
				ipaddresses.push_back(temp);
			}
			
			int num_ports=ports.size();
			int num_address=ipaddresses.size();
			for(int i=ports[0];i<=ports[num_ports-1];i++) // Iterating over all the ports
			{
			   if(num_address==1) // If there is only one IPaddress
			   {
			   	 vector<int> address_parts;// Stores the 4 parts of the IP address
			   	 stringstream strstream(ipaddresses[0]);
			   	 string temp;
			   	 while(getline(strstream,temp,'.'))// separates the IP address, based on the . delimiter
				{
					stringstream str_int(temp);
					int val;
					str_int>>val;
					address_parts.push_back((int)val);
				}
				//Sets the corresponding (dir, protocol, port, IPaddress (4 parts) ) to true
				mp[make_pair(dir,make_pair(protocol,make_pair(i,make_pair(address_parts[0], make_pair(address_parts[1],make_pair(address_parts[2],address_parts[3]))) )))]=true;
			   }else
			   {
			      	vector<int> begin_address;// Stores the 4 parts of the starting IPaddress
				   	stringstream strstreambegin(ipaddresses[0]);
				   	string temp;
				   	while(getline(strstreambegin,temp,'.'))
					 {
						stringstream str_int(temp);
						int val;
						str_int>>val;
						begin_address.push_back((int)val);
					 } 
			      	
					vector<int> end_address;// Stores the 4 parts of the ending IPaddress
			      	stringstream strstreamend(ipaddresses[1]);
			      	while(getline(strstreamend,temp,'.'))
					 {
						stringstream str_int(temp);
						int val;
						str_int>>val;
						end_address.push_back((int)val);
					 }
					 
					unsigned int startIP= (begin_address[0] << 24 | begin_address[1] << 16 | begin_address[2] << 8 | begin_address[3]);// Converting the 4 parts of the beginning IPaddress to a single number for easy iteration
				    unsigned int endIP= ( end_address[0] << 24 | end_address[1] << 16 | end_address[2] << 8 | end_address[3]);// Converting the 4 parts of the ending IPaddress to a single number for easy iteration
			        unsigned int iterator;
			        for (iterator=startIP; iterator <= endIP; iterator++)
				    {
				    	//Sets the corresponding (dir, protocol, port, IPaddress (4 parts) ) to true
				       	mp[make_pair(dir,make_pair(protocol,make_pair(i,make_pair((int)((iterator & 0xFF000000)>>24), make_pair((int)((iterator & 0x00FF0000)>>16),make_pair((int)((iterator & 0x0000FF00)>>8),(int)((iterator & 0x000000FF)))) ))))]=true; 
				    }
			   }	
			}
		}
	}
	public:
		Firewall(string path)
		{
			//Gets the path of the CSV file from the constructor
			this->path=path;
			addFirewall();// Calls the method addFirewall
		}
		bool accept_packet(string dirn,string cur_protocol,int port, string address) //Method to check whether the packet is valid or not
		{
			 vector<int> address_parts;// Stores the 4 parts of the IPaddress
		   	 stringstream strstream(address);
		   	 string temp;
		   	 while(getline(strstream,temp,'.'))
			{
				stringstream str_int(temp);
				int val;
				str_int>>val;
				address_parts.push_back((int)val);
			}
			
			bool dir=directions[dirn];
			bool protocol=protocols[cur_protocol];
			//Checks the Ordered Map Data Structure to see if the packet can pass and return true and false accordingly
			return 	mp[make_pair(dir,make_pair(protocol,make_pair(port,make_pair(address_parts[0], make_pair(address_parts[1],make_pair(address_parts[2],address_parts[3]))) )))];
		}
		
};
int main()
{
	Firewall fw("Rules.csv");
	cout<<fw.accept_packet("inbound", "tcp", 80, "192.168.1.2");
	cout<<fw.accept_packet("inbound", "udp", 53, "192.168.2.1");
	cout<<fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11");
	cout<<fw.accept_packet("inbound", "tcp", 81, "192.168.1.2");
	cout<<fw.accept_packet("inbound", "udp", 24, "52.12.48.92");
	return 0;
}
