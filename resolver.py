import sys
import socket
import getopt
import random

from struct import *


"""
DNS MESSAGE
    ID:             2 Bytes
    Control:        2 Bytes
    # Questions:    2 Bytes
    # Answers:      2 Bytes
    # Auth:         2 Bytes
    # Addtl:        2 Bytes

    Questions       ...
    Answers         ...
    Auth            ...
    Addtl           ...
"""


def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """

    # ls is a string array
    ls = orig_string.split('.')
    toReturn = b""
    
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start (int): the location within the message where the network string
            starts.

    Returns:
        string: The human readable string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) will return
              'www.sandiego.edu'
    """

    toReturn = ""
    position = start
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            for i in range(6) :
                offset += (length & 1 << i) << 8

            for i in range(8):
                offset += (b2 & 1 << i)
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length

    return toReturn[:-1], position
    

def constructQuery(hostname, qtype):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        hostname (string): What we're asking for

    Returns: 
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

   
    # create a query with a random id for the hostnames IP addr
    ID = random.randint(0, 65535) 
    #print("ID CREATED: " + str(ID))
  
    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
            num_other)

    print("Constructing query for " + hostname)
    
    qname = stringToNetwork(hostname)

    remainder = pack("!HH", qtype, 1)
    query = header + qname + remainder
    return query

def unpackQuery(received_q, hostname, qtype, const_type):
    """
    Unpacks a Received Query 

    Args:
        received_q (string): The received query to unpack

    Returns:
        string: unpacked data
    """
    index = 0 
    # Extract the header of the message
    header   = received_q[:12]  # First 12 bytes
    response = received_q[12:60]
    # All unpacked first for the header
    ID, flags, num_questions, num_answers, num_auth, num_other = unpack("!HHHHHH", header)
    index = 12
    
    """
    print("=== HEADER INFO ===")    
    print("ID: " + str(ID))
    print("Flags: " + str(flags))
    print("Questions: " + str(num_questions))
    print("Answers: " + str(num_answers))
    print("Auth: " + str(num_auth))
    print("Other: " + str(num_other))
    print()
    #"""
    
    # Get through the query section
    index = parseQuestions(num_questions, index, received_q)
  
    # Parse answers here
    answer_list = []
    cname       = False
    mx          = False
    for i in range(num_answers):
        index, answer, atype = parseRecords(index, received_q, 3)
        if atype == 5 and qtype == 1:
            cname = True
        elif atype == 5 and qtype == 15:
            mx = True
        elif atype == 15 and qtype == 15:
            mx = True
        elif atype == 6:
            print("SOA: could not resolve")
            return [] , False, True
        
        answer_list.append(answer)

    # Restart if we receive an mx or cname answer
    if cname or mx:
        return answer_list, True, False
    elif answer_list != []:
        print("DONE")
        print("==========")
        return answer_list, False, True

    auth_list = []
    addl_list = []
    
    # Authoritative Section
    for i in range(num_auth):
        index, auth, atype = parseRecords(index, received_q, 1)
        if atype == 6:
            print("SOA: Could not resolve")
            return [], False, False
        else:
            auth_list.append(auth)
    
    # Additional Section
    for i in range(num_other):
        index, addl, atype = parseRecords(index, received_q, 2)
        
        if atype == 28: # IPV6 Address: need to skip cause we don't handle it
            #print("skipping")
            --i;
            continue
        elif atype == 6:
            print("SOA: Could not resolve")
            return [], False, False
        else:
            addl_list.append(addl)

    # return the list of new servers to query
    if num_answers > 0:
        return answer_list, False, False
    elif num_auth > 0:
        return auth_list, False, False
    elif num_addl > 0:
        return addl_list, False, False
    else:
        return [], False, True

def parseQuestions(num_questions, index, response):
    """
    Takes in the index where the question section starts and spits out the index where the questions end

    Arguments:
	num_questions (int): The number of questions
	index (int): The index where the question section starts
	response (bytes): The response to parse

    Returns:
	The index where the question section ends
    """

    for i in range(num_questions):
        question, index = networkToString(response, index)
        qtype, qclass = unpack("HH", response[index:index + 4])
        index += 4 
        
        """
        print()
        print("Question: " + question)
        print("Type: " + str(qtype))
        print("Class: " + str(qclass))
        print()
	    #"""

    return index

def parseRecords(index, response, rr_type):
    """

    Takes in the index where a record starts and spits out the index where the questions end

    Arguments:
	index (int): The index where the question section starts
	response (bytes): The response to parse
    rr_type (int): The type of resource record we are parsing
        1 = authoritative
        2 = additional
        3 = answer

    Returns:
	The index where the question section ends
	The next server to query
	The type of record parsed
    """

    a_name, index = networkToString(response, index);
    a_type, a_class, a_ttl, a_len = unpack("!HHIH", response[index:index + 10])
    index += 10
    
    if a_type == 15:
        pref = unpack("!H", response[index:index + 2])
        index += 2
     
    """ 
    print("Name: " + str(a_name))
    print("Type: " + str(a_type))
    print("Class: " + str(a_class))
    print("TTL: " + str(a_ttl))
    print("Length: " + str(a_len))
    print()
    #"""

    if rr_type == 1:
        a_data, index = networkToString(response, index)
        #print("AUTH: " + a_data)
        return index, a_data, a_type
    
    elif rr_type == 2:
        # IPv4 vs IPv6 types get parsed differently
        if a_type == 28:
            ip1, ip2, ip3, ip4 = unpack("IIII", response[index:index + 16])
            index += 16
        else:
            ip1, ip2, ip3, ip4 = unpack("BBBB", response[index:index + 4])
            index += 4

        ip_addr = str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)
        #print("ADDNL: " + str(ip_addr))
        return index, ip_addr, a_type

    else: # rr_type == 3 which is answers
        if a_type == 1: # A type
            ip1, ip2, ip3, ip4 = unpack("BBBB", response[index:index + 4])
            ip_addr = str(ip1) + "." + str(ip2) + "." + str(ip3) + "." + str(ip4)
            index += 4
            print("ANSWER: " + ip_addr) 
            return index, ip_addr, a_type
        
        elif a_type == 5:
            cname, index = networkToString(response, index)
            #print("CNAME: " + cname)
            return index, cname, a_type       

        elif a_type == 15:
            mail_name, index = networkToString(response, index)
            #print("MX: " + mail_name)
            return index, mail_name, a_type
        
        else:
            print("Error")
            exit()

def recursiveQuery(servers_to_query, hostname, qtype, const_type):
    """
    Recursively search through the queries

    Arguments:
	sendto (string): The query to send to
	query (bytes): The query to send
	hostname (string): The hostname that is being queried
	qtype (int): The type of query

    Returns:
	Boolean if the query has been resolved
	Boolean if the query returned a canonical name
	Boolean if the query was a mail server query
	New Hostname to query for (for mx and canonical queries)
    """

    for server in servers_to_query:
        query = constructQuery(hostname, qtype)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)   # socket should timeout after 5 seconds
    
        try:
            # send the message to the desired address 
            sock.sendto(query, (server, 53))
            print("SENT TO: " + server)

            response = sock.recv(4096)
            print("Recieved Response! Unpacking your Query Now... ")
            print()
    
            # You'll need to unpack any response you get using the unpack function
            new_server_list, restart, done = unpackQuery(response, hostname,
            qtype, const_type)
            
            # Determine the next step or just move onto the next iteration
            if restart:
                return new_server_list, True, False
            
            elif done:
                return new_server_list, False, True
                          
            elif new_server_list == []:
                print("EMPTY")
                return [], False, True

            else:
                return recursiveQuery(new_server_list, hostname, qtype, const_type)

        except socket.timeout as e:
            print("Exception:", e)
            print("Next IP Addr");

def rootServerList():
    """
    Generates a list of root dns server IP addresses

    Args: None

    Returns:
        The list of server IP addresses
    """

    # Open a file in read mode
    file_object = open("root-servers.txt", "r");
    root_server_list = []

    for line in file_object:
        # Need to save each IP address and return it: cut off the \n at the
        # end of each line
        #print(line)
        root_server_list.append(line[:-1])

    return root_server_list


def main(argv=None):
    if argv is None:
        argv = sys.argv

    # Check Command Line Length
    if (len(argv) <= 1) or (len(argv) > 3):
        print("Error in command line: too many/too little arguments")
        sys.exit(2)

    # Check the command line args
    try:
        opts, args = getopt.getopt(sys.argv[1:], "m:")
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    # Get/Save the command line args
    to_query = argv[1]
    qtype = 1 # A type by default
    for opt, arg in opts:
        if opt in ('-m', '--mail'):
            # Set to 15  means mx query as specified by write up
            print("Mail Server Query")
            qtype	= 15
            to_query	= arg

    print("Searching for: " + to_query)

    # Need to get a list of root servers
    root_server_list = rootServerList()
    print("First ip addr to send to: " + str(root_server_list[0]))
    
    # Start the recursion for an iterative search
    restart = True
    done = False
    answer_list = []
    og_qtype = qtype
    og_query = to_query
    while restart and not done:
        answer_list, restart, done = recursiveQuery(root_server_list, to_query, qtype, og_qtype)
        if restart:
            print("RESTARTING")
            print("==========")
            qtype = 1
            to_query = answer_list[0]

    if answer_list != []:
        print(og_query + " resolves to: ")
        for answer in answer_list:
            print(answer)

if __name__ == "__main__":
    sys.exit(main())

