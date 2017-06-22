snort-scripts
=============

Scripts for parsing snort logs. 

<strong>getS5HostInfo.php</strong>

In order to implement the script you must download both the getS5HostInfo.php and the PHPColors.php file. If you do not have the PHPColors.php file in the same directory as the getS5HostInfo.php it will throw errors.

<strong>About the Script</strong> 

The script can be used for multiple purposes.  The script is used to read and display information about stream5 messages logged by snort.  An example of a stream5 message is given below:

 

Nov  7 04:02:14 3D-Hostname snort[15361]: S5: Pruned session from cache that was using 1103878 bytes (stale/timeout). 192.168.182.34 48566 --> 10.119.55.240 22 (9) : LWstate 0x8e LWFlags 0x216002

Snort will log these type of messages depending on the settings configured in the TCP Stream Configuration settings.  Typically, if you see a lot of these messages it means that the traffic being seen is asymmetric/one sided traffic or in general, only parts of the sessions are being seen by snort.  This type of traffic can cause performance problems with snort, and should be addressed. 

 

<strong>Options</strong>

 

Running the script with the -h or --help option will display the following:

 

getS5HostInfo.php

Version 1.3
Usage: getS5HostInfo [options] [--] [args...] <file> 

This script accepts a syslog (messages) file and prints information about stream5 sessions.
This version of the script was written based on open source snort version 2.9.6.

Options:
	--csv <filename>	Get all S5 info from a syslog file and create a csv file.
	-h --help		This help
	--limit <limit>		Set the limit for the number of sessions/hosts to display in the summary (useless without --summary). (default is 50)
	--LWFlags <hex>		Print the session flag map for the given hex string. The leading 0x is optional. Max 32 bit hex string accepted.
	--LWstate <hex>		Print the stream5 state map for the given hex string. The leading 0x is optional. Max 16 bit hex string accepted.
	-m state|flag		Prints the mapping of the stream5 states or flags
	-s			Silent mode. Will not output summaries to screen.
	--summary <csv_file>	Print the summary of stats contained within a csv file. CSV must have been created by this script, or in the same format.
	--all-data 		Pull stats from all S5 messages. By default it will only pull data from S5 prunes. (meaningless without --csv)
	--script-stats 		Print stats for script. i.e. memory use and runtime.



<strong>Quick Start Guide</strong>

 

In general, the script is most useful for generating a summary of the stream5 sessions in syslog files.  This can be quickly accomplished with the following steps:

 

1) Generate a csv file from a syslog file:

 

[jgroetzi@tex2 var-log]$ getS5HostInfo --csv messages

...

CSV file: Sourcefire3D-1418529731-S5Info-549312c2f1039.csv

2) Generate the summary:

 

[jgroetzi@tex2 var-log]$ getS5HostInfo --summary Sourcefire3D-1418529731-S5Info-549312c2f1039.csv

...

Output summary file: 'summary-5493137b89ab6'

The summary will be printed to screen (by default) as well as to the 'summary-5493137b89ab6' file.  For details on the output and additional usage, see the "Detailed Usage" section below.

 

Detailed Usage:

 

Below is a listing of the different ways the script can be used:

 

The bit maps

 

There are two types of bit maps, the session state map and the session flag map.  In certain S5 messages, the state and flag values will be printed.  These are a set of flags that are set on the stream by snort and can contain useful information about the session.  In the example given above (in the About section), the values being referred to are "LWstate 0x8e LWFlags 0x216002".  Since this is a hex byte representation of the flags, it is not very human readable.  Passsing the script the -m option will print an example of the bit map (i.e. getS5HostInfo -m state).  You can also pass the script specifc values and it will print the map for those byte values.  If you want to view the maps for a specific message from syslog, you can pass the script the "--LWstate" and "--LWFlags" options.  From the example given above, you would run the following command to print the bit maps for the session:

 

getS5HostInfo --LWstate 0x8e --LWFlags 0x216002

These options were used so that strings from literal messages could be copy an pasted to the script (just add the leading "--" to each option).  Running this will output the following:

 +==================+ Stream5 State Map +==============-====+  

	hex: 0x8e
    binary: 00000000 10001110

	##) 00000000 10001110
	    |||||||| ||||||||
	01) |||||||| |||||||+-- STREAM5_STATE_SYN
	02) |||||||| ||||||+--- STREAM5_STATE_SYN_ACK
	03) |||||||| |||||+---- STREAM5_STATE_ACK
	04) |||||||| ||||+----- STREAM5_STATE_ESTABLISHED
	05) |||||||| |||+------ STREAM5_STATE_DROP_CLIENT
	06) |||||||| ||+------- STREAM5_STATE_DROP_SERVER
	07) |||||||| |+-------- STREAM5_STATE_MIDSTREAM
	08) |||||||| +--------- STREAM5_STATE_TIMEDOUT
	    ||||||||
	09) |||||||+---------- STREAM5_STATE_UNREACH
	    ||||||+
	    |||||+
	10) ||||+-------------- STREAM5_STATE_CLOSED
	11) 00000000 00000000-- STREAM5_STATE_NONE


+==================+ Session Flag Map +==================+  

	hex: 0x216002
    binary: 00000000 00100001 01100000 00000010

	##) 00000000 00100001 01100000 00000010
	    |||||||| |||||||| |||||||| ||||||||
	11) |||||||| |||||||| |||||||| |||||||+-- SSNFLAG_SEEN_CLIENT
	12) |||||||| |||||||| |||||||| ||||||+--- SSNFLAG_SEEN_SERVER
	13) |||||||| |||||||| |||||||| |||||+---- SSNFLAG_ESTABLISHED
	14) |||||||| |||||||| |||||||| ||||+----- SSNFLAG_NMAP
	15) |||||||| |||||||| |||||||| |||+------ SSNFLAG_ECN_CLIENT_QUERY
	16) |||||||| |||||||| |||||||| ||+------- SSNFLAG_ECN_SERVER_REPLY
	17) |||||||| |||||||| |||||||| |+-------- SSNFLAG_HTTP_1_1
	18) |||||||| |||||||| |||||||| +--------- SSNFLAG_SEEN_PMATCH
	    |||||||| |||||||| ||||||||
	19) |||||||| |||||||| |||||||+---------- SSNFLAG_MIDSTREAM
	11) |||||||| |||||||| ||||||+----------- SSNFLAG_CLIENT_FIN
	11) |||||||| |||||||| |||||+------------ SSNFLAG_SERVER_FIN
	12) |||||||| |||||||| ||||+------------- SSNFLAG_CLIENT_PKT
	13) |||||||| |||||||| |||+-------------- SSNFLAG_SERVER_PKT
	14) |||||||| |||||||| ||+--------------- SSNFLAG_COUNTED_INITIALIZE
	15) |||||||| |||||||| |+---------------- SSNFLAG_COUNTED_ESTABLISH
	16) |||||||| |||||||| +----------------- SSNFLAG_COUNTED_CLOSING
	    |||||||| ||||||||
	17) |||||||| |||||||+------------------- SSNFLAG_TIMEDOUT
	18) |||||||| ||||||+-------------------- SSNFLAG_PRUNED
	19) |||||||| |||||+--------------------- SSNFLAG_RESET
	20) |||||||| ||||+---------------------- SSNFLAG_DROP_CLIENT
	21) |||||||| |||+----------------------- SSNFLAG_DROP_SERVER
	22) |||||||| ||+------------------------ SSNFLAG_LOGGED_QUEUE_FULL
	23) |||||||| |+------------------------- SSNFLAG_STREAM_ORDER_BAD
	22) |||||||| +-------------------------- SSNFLAG_FORCE_BLOCK
	    ||||||||
	23) |||||||+---------------------------- SSNFLAG_CLIENT_SWAP
	22) ||||||+----------------------------- SSNFLAG_CLIENT_SWAPPED
	27) 11111111 11111111 11111111 11111111-- SSNFLAG_ALL
	28) 00000000 00000000 00000000 00000000-- SSNFLAG_NONE


Note: When running this in a terminal the map will color the flags that are set making it easier to see then the above example.
 

Screen Shot 2014-12-08 at 3.54.17 PM (2).png

Screen Shot 2014-12-08 at 3.54.25 PM.png

 

This shows a bit map for the various flags that each bit represents in the hex string.  In this example the following bits are set in the session state string:

 

-STREAM5_STATE_SYN_ACK

-STREAM5_STATE_ACK

-STREAM5_STATE_ESTABLISHED

-STREAM5_STATE_TIMEDOUT

 

And the following flags are set in the flag string:

 

-STREAM5_STATE_TIMEDOUT

-SSNFLAG_COUNTED_INITIALIZE

-SSNFLAG_COUNTED_ESTABLISH

-SSNFLAG_TIMEDOUT

-SSNFLAG_LOGGED_QUEUE_FULL

 

In this example, you can see that snort only saw one side of the session (server side).  Snort never saw the initial syn from the client (STREAM5_STATE_SYN is not set), and it also never saw a single packet from the client (since SSNFLAG_SEEN_CLIENT is not set). This is the type of traffic we are looking for since it is one sided, which typically indicates asynchrounous traffic (or one sided traffic).

 

Getting a summary of the data

 

The bit maps are helpful for seeing and understanding what flags are set in specific sessions, but this would be too tedious to do for each S5 message in syslog, so the script provides a way to aggregate the data and get a summary of all of the S5 sessions logged to syslog. 

 

Step 1: Generate a CSV file

 

The first thing you want to do is generate a csv file using the "--csv" option in the script.  It is important to note that the script will only pull information from S5 messages that are prunes (by default).  The reason for this is to avoid duplicate data, which can scew the results. A session will get logged to syslog when it reaches the max queued bytes/segments, it will also get logged when it times out.  Typically, if the session exceeds the max_queued_bytes or max_queued_segments, it is likely that we are only seeing one side of the conversation, so snort will likely never see the full end of the session and a message will also be logged when it times out, so each session typcially has 2 messages logged.  Since the prune occurs last, data is pulled from these messages because they contain all flags set over the lifetime of the session and the flags set will be the final state.  If you want to override this behavior and have the script pull stats from all of the valid S5 messages, you can pass the "--all-data" flag when you run the command to generate the CSV. 

 

For example:

 

To generate csv file with default settings run:

 

getS5HostInfo --csv messages

 

To generate a csv file with all of the available data, run:

 

getS5HostInfo --all-data --csv messages

 

This will generate a csv file which contains all of the relevant S5 data.  The filename that is created will be in the following format:

 

<hostname>-<epoch_ts_of_first_message>-S5Info-uuid.csv

 

hostname - the hostname of the device (taken from the syslog messages).

epoch_ts_of_first_message - The epoch timestamp of the very first message in the syslog file.

uuid - a randomly generated uuid.

 
Process Multiple Files

 

The script only accepts one file at a time.  If you want to aggregrate the data from multiple syslog files, you can just concatenate one csv file into another. I recommend making an "all.csv" file and dumping all of the csv files into this file to avoid confusion.  For example:

 

[jgroetzi@tex2 var-log]$ getS5HostInfo --csv messages

...

CSV file: CD1IPS-INTBE1A-1415332927-S5Info-54861777aaba7.csv

 

[jgroetzi@tex2 var-log]$ getS5HostInfo --csv messages.1

 

CSV file: CD1IPS-INTBE1A-1415160126-S5Info-548619065b14d.csv

 

[jgroetzi@tex2 var-log]$ cat CD1IPS-INTBE1A-1415332927-S5Info-54861777aaba7.csv >> all.csv

[jgroetzi@tex2 var-log]$ cat CD1IPS-INTBE1A-1415160126-S5Info-548619065b14d.csv >> all.csv

 

Step 2: Generate the summary data

 

Once you have your csv file generated, you can generate a summary of the data using the "--summary" option.  By default, the script will print the summary to screen and to a summary file.  The name of the summary file will be "summary-<random_uuid>.  If you do not want this to print the summary to screen, pass the "-s" option to the script to put it into "silent" mode.  Examples:

 

Print to screen and summary file:

 

[jgroetzi@tex2 var-log]$ getS5HostInfo --summary all.csv

 

Only print to summary file:

 

[jgroetzi@tex2 var-log]$ getS5HostInfo -s --summary all.csv

 

Step 3: Reading the Results

 

The summary report includes the following sections:

 

-Top sessions for syn_no_syn_ack - Top sessions where snort saw the initial syn, but did not see the initial syn/ack.

-Top sessions for syn_ack_no_syn - Top sessions where snort saw the syn_ack, but did not see the initial syn.

-Top sessions for client_no_server_count - Top sessions where snort saw traffic from the client, but never saw traffic from the server.
-Top sessions for server_no_client_count - Top sessions where snort saw traffic from the server, but never saw traffic from the client.
-Top Source ports seen - Listing of the top source ports seen and their count.
-Top Dest ports seen - Listing of the top destination ports seen and their count.
-Top Application Protocols Seen - List and count of top application protocols seen.
-Stream5 State Summary - Summary of what S5 states were set.

-Session Flags Summary - Summary of what S5 session flags were set.

 

By default, the first 3 sections will be limited to the top 50.  If you want to override the limit, just pass the script the "--limit" flag followed by the limit you want to set (i.e. "getS5HostInfo --limit 100 --summary all.csv" will set the limit to the top 100).

 

Example Output

 

Let's look at an example of summary output:

 

Top 50 sessions for syn_no_syn_ack:
1 ) 172.23.128.237  -> 10.119.5.211    : 7
2 ) 10.121.135.14   -> 217.148.73.34   : 7
3 ) 10.121.135.14   -> 10.119.22.17    : 3
4 ) 10.121.135.19   -> 217.148.73.67   : 2
5 ) 10.121.135.19   -> 217.148.73.34   : 2

...

 

Top 50 sessions for syn_ack_no_syn:
1 ) 192.168.182.34  -> 10.119.56.11    : 20834
2 ) 192.168.182.34  -> 10.119.55.240   : 18401
3 ) 192.168.182.34  -> 10.119.56.12    : 8870
4 ) 192.168.182.34  -> 10.119.56.13    : 8821
5 ) 192.168.182.34  -> 10.119.55.244   : 6462

....

 

Top 50 sessions for client_no_server_count:
1 ) 10.241.40.95    -> 10.119.5.201    : 15
2 ) 10.121.135.14   -> 217.148.73.34   : 8
3 ) 10.241.155.30   -> 10.119.5.201    : 7
4 ) 172.23.128.237  -> 10.119.5.211    : 7
5 ) 10.121.135.19   -> 217.148.73.34   : 4

....

 

Top 50 sessions for server_no_client_count:
1 ) 192.168.182.34  -> 10.119.56.11    : 20834
2 ) 192.168.182.34  -> 10.119.55.240   : 18401
3 ) 192.168.182.34  -> 10.119.56.12    : 8870
4 ) 192.168.182.34  -> 10.119.56.13    : 8821
5 ) 192.168.182.34  -> 10.119.55.244   : 6462

...

 

Top Source ports seen:
Port : Times Seen
1 ) 33911    : 12
2 ) 42401    : 12
3 ) 33314    : 11
4 ) 58964    : 11
5 ) 45533    : 11

...

 

Top Dest ports seen:
Port : Times Seen
1 ) 22       : 85869
2 ) 8080     : 1164
3 ) 5632     : 935
4 ) 25       : 69
5 ) 1344     : 37

...

 

Top Application Protocols Seen:
AppID : Times Seen
1 ) 9        : 86804
2 ) 5        : 1180
3 ) 8        : 67
4 ) 19       : 20
5 ) 33       : 3

....

 

=========================================
Stream5 State Summary
=========================================
Time: 2014-11-05 04:02:18 - 2014-11-07 22:19:45
Total Sessions           :  88139
Saw Client but not Server:  104 (0%)
Saw Server but not Client:  88005 (99%)
Saw Client and Server    :  30 (0%)
STREAM5_STATE_ESTABLISHED:  88005 (99.85%)
STREAM5_STATE_DROP_CLIENT:  0 (0.00%)
STREAM5_STATE_DROP_SERVER:  0 (0.00%)
STREAM5_STATE_MIDSTREAM  :  104 (0.12%)
STREAM5_STATE_TIMEDOUT   :  26419 (29.97%)
STREAM5_STATE_UNREACH    :  0 (0.00%)
STREAM5_STATE_CLOSED     :  0 (0.00%)

 

=========================================
 Session Flags Summary
=========================================
Time: 2014-11-05 04:02:18 - 2014-11-07 22:19:45
Total Sessions            :  88139
Saw SYN but not SYN_ACK   :  35 (0%)
Saw SYN_ACK but not SYN   :  87978 (99%)
Saw SYN and SYN_ACK       :  22 (0%)
Saw 3-Way Handshake       :  22 (0%)
SSNFLAG_ESTABLISHED       :  7 (0.01%)
SSNFLAG_NMAP              :  0 (0.00%)
SSNFLAG_ECN_CLIENT_QUERY  :  0 (0.00%)
SSNFLAG_ECN_SERVER_REPLY  :  0 (0.00%)
SSNFLAG_HTTP_1_1          :  0 (0.00%)
SSNFLAG_SEEN_PMATCH       :  0 (0.00%)
SSNFLAG_MIDSTREAM         :  104 (0.12%)
SSNFLAG_CLIENT_FIN        :  0 (0.00%)
SSNFLAG_SERVER_FIN        :  0 (0.00%)
SSNFLAG_CLIENT_PKT        :  0 (0.00%)
SSNFLAG_SERVER_PKT        :  0 (0.00%)
SSNFLAG_COUNTED_INITIALIZE:  88138 (100.00%)
SSNFLAG_COUNTED_ESTABLISH :  88000 (99.84%)
SSNFLAG_COUNTED_CLOSING   :  62012 (70.36%)
SSNFLAG_TIMEDOUT          :  88138 (100.00%)
SSNFLAG_PRUNED            :  0 (0.00%)
SSNFLAG_RESET             :  28 (0.03%)
SSNFLAG_DROP_CLIENT       :  0 (0.00%)
SSNFLAG_DROP_SERVER       :  0 (0.00%)
SSNFLAG_LOGGED_QUEUE_FULL :  86445 (98.08%)
SSNFLAG_STREAM_ORDER_BAD  :  142 (0.16%)
SSNFLAG_FORCE_BLOCK       :  0 (0.00%)
SSNFLAG_CLIENT_SWAP       :  0 (0.00%)
SSNFLAG_CLIENT_SWAPPED    :  0 (0.00%)

 

 

Top sessions for syn_no_syn_ack

 

Client.IP -> Server.IP : number of sessions pruned.

 

This will show the top sessions where snort saw the initial syn packet from the client, but did not see the following syn/ack back from the server.  Typically we wouldn't care about seeing just a syn and no syn/ack as portscanning traffic will look like this, however in this case we are interested in this data because the S5 messages are only logged if snort has seen 1MB or  2601 segments (by default, but configurable) of traffic in this stream without seeing an ack from the other side.  So that means snort saw the initial syn AND at least 1MB (or 2601 segmnets) of data from the client, with no subsequent ack from the server.  So the traffic being logged here is very unlikely to be port scanning traffic. This can indicate "bad" traffic and potentially asynchronous traffic.

 

Top sessions for syn_ack_no_syn

Client.IP -> Server.IP : number of sessions pruned.

 

This will show the top sessions where snort saw the initial syn/ack packet from the server, but did not see the preceeding syn from the client. This can indicate "bad" traffic and potentially asynchronous traffic.

 

Top sessions for client_no_server_count

Client.IP -> Server.IP : number of sessions pruned.

 

This shows the sessions where snort saw traffic from the Client.IP ONLY.  For sessions appearing in this list, snort never saw a single packet from the Server.IP.  These sessions are very likely to be asynchronous.

 

Top sessions for server_no_client_count

Client.IP -> Server.IP : number of sessions pruned.

 

This shows the sessions where snort saw traffic from the Server.IP ONLY.  For sessions appearing in this list, snort never saw a single packet from the Client.IP.  These sessions are very likely to be asynchronous.

 

Top Source ports seen

Port : Times Seen

 

This section lists the top source ports seen.  This probably won't be of much use, but it may help indicate what services are asynchrounous.
 

Top Dest ports seen

Port : Times Seen

 

This section lists the top destination ports seen.  This probably won't be of much use, but it may help indicate what services are asynchrounous.

 

Top Application Protocols Seen

AppID : Times Seen

 

This lists the top AppIDs that snort reported with the sessions.  At this time I am unsure of where the mapping is, so this is reserved for future use and will be updated once there is a mapping.  It is not of much use currently.

 

Stream5 State Summary

 

This section lists the stream5 states summary.  This section is useful for getting an overall picture of the states set in the sessions. For example, if you see a high percent for "Saw Client but not Server" then this indicates that snort is only seeing the client side of traffic and you should refer to the "top sessions for client_no_server_count" section for a list of the sessions.  In the example above, less than 1% of the sessions logged only saw the client and 99% of the sessions Saw the Server but not the Client, so the ""top sessions for server_no_client_count" section should be refered to.
 

Session Flags Summary

 

This section lists the session flags summary.  This section is useful for getting an overall picture of the flags set in the sessions. This will give you some additional information on the traffic by looking for patterns on what flags are set the most often.

 

Example Summary/Take Aways
 

From this specific example, it can be determined that there is a problem with this traffic.  The problem appears to be that there is asynchronous traffic where the device is only seeing traffic from the servers, and is not seeing traffic from the clients. The customer should be provided with a list of the top sessions for server_no_client so that they can investigate why this traffic is not being seen by our device.
