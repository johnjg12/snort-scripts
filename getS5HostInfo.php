#!/usr/bin/php

<?php
/*
 * getS5HostInfo.php
 * Author: John Groetzinger
 * Description: This script prints the mapping of stream5 states and session flags.
 * It takes hex values as an arguement and prints the mapping for that hex string
 * It also accepts a syslog file containing snort stream5 messages and creates a csv file
 * which can then be used to generate statistics on the traffic depending on the arguements 
 * provided to the script.
 * 
 * This was written based off of snort version 2.9.6
 */ 

ini_set('memory_limit', '6000M');
error_reporting(E_ERROR);
require_once("PHPColors.php");

$colors = new Colors();

 /*
  * Global Variables
  */ 
$VERSION = "1.3";
$csv_header = "timestamp,pid,srcIP,srcPort,dstIP,dstPort,appProto,s5sn,s5ss,s5ssa,s5sa,s5se,s5sdc,s5sds,s5sm,s5st,s5su,s5sc,".
              "sfsc,sfssrv,sfe,sfnmap,sfecq,sfesr,sfhttp,sfspmat,sfm,sfcf,sfsf,sfcp,sfsp,sfci,sfce,sfcc,sft,sfp,sfr,sfdc,sfds,".
              "sflqf,sfsob,sffb,sfcs,sfcsd,sfa,sfn";
$sort_key = "";      
/* 
 * Define session states
 */
define("STREAM5_STATE_NONE",                  0x0000);
define("STREAM5_STATE_SYN",                   0x0001);
define("STREAM5_STATE_SYN_ACK",               0x0002);
define("STREAM5_STATE_ACK",                   0x0004);
define("STREAM5_STATE_ESTABLISHED",           0x0008);
define("STREAM5_STATE_DROP_CLIENT",           0x0010);
define("STREAM5_STATE_DROP_SERVER",           0x0020);
define("STREAM5_STATE_MIDSTREAM",             0x0040);
define("STREAM5_STATE_TIMEDOUT",              0x0080);
define("STREAM5_STATE_UNREACH",               0x0100);
define("STREAM5_STATE_CLOSED",                0x0800);

//array containing all states except none
$state_array = array("STREAM5_STATE_SYN" => STREAM5_STATE_SYN,
                     "STREAM5_STATE_SYN_ACK" => STREAM5_STATE_SYN_ACK,
                     "STREAM5_STATE_ACK" => STREAM5_STATE_ACK,
                     "STREAM5_STATE_ESTABLISHED" => STREAM5_STATE_ESTABLISHED,
                     "STREAM5_STATE_DROP_CLIENT" => STREAM5_STATE_DROP_CLIENT,
                     "STREAM5_STATE_DROP_SERVER" => STREAM5_STATE_DROP_SERVER,
                     "STREAM5_STATE_MIDSTREAM" => STREAM5_STATE_MIDSTREAM,
                     "STREAM5_STATE_TIMEDOUT" => STREAM5_STATE_TIMEDOUT,
                     "STREAM5_STATE_UNREACH" => STREAM5_STATE_UNREACH,
                     "STREAM5_STATE_CLOSED" => STREAM5_STATE_CLOSED);
                     
/*****************************************************************************/

 /* 
 * Define session flags
 */ 
define("SSNFLAG_SEEN_CLIENT",         0x00000001);
//define("SSNFLAG_SEEN_SENDER",         0x00000001);
define("SSNFLAG_SEEN_SERVER",         0x00000002);
//define("SSNFLAG_SEEN_RESPONDER",      0x00000002);
define("SSNFLAG_ESTABLISHED",         0x00000004);
define("SSNFLAG_NMAP",                0x00000008);
define("SSNFLAG_ECN_CLIENT_QUERY",    0x00000010);
define("SSNFLAG_ECN_SERVER_REPLY",    0x00000020);
define("SSNFLAG_HTTP_1_1",            0x00000040); /* has stream seen HTTP 1.1? */
define("SSNFLAG_SEEN_PMATCH",         0x00000080); /* seen pattern match? */
define("SSNFLAG_MIDSTREAM",           0x00000100); /* picked up midstream */
define("SSNFLAG_CLIENT_FIN",          0x00000200); /* server sent fin */
define("SSNFLAG_SERVER_FIN",          0x00000400); /* client sent fin */
define("SSNFLAG_CLIENT_PKT",          0x00000800); /* packet is from the client */
define("SSNFLAG_SERVER_PKT",          0x00001000); /* packet is from the server */
define("SSNFLAG_COUNTED_INITIALIZE",  0x00002000);
define("SSNFLAG_COUNTED_ESTABLISH",   0x00004000);
define("SSNFLAG_COUNTED_CLOSING",     0x00008000);
define("SSNFLAG_TIMEDOUT",            0x00010000);
define("SSNFLAG_PRUNED",              0x00020000);
define("SSNFLAG_RESET",               0x00040000);
define("SSNFLAG_DROP_CLIENT",         0x00080000);
define("SSNFLAG_DROP_SERVER",         0x00100000);
define("SSNFLAG_LOGGED_QUEUE_FULL",   0x00200000);
define("SSNFLAG_STREAM_ORDER_BAD",    0x00400000);
define("SSNFLAG_FORCE_BLOCK",         0x00800000);
define("SSNFLAG_CLIENT_SWAP",         0x01000000);
define("SSNFLAG_CLIENT_SWAPPED",      0x02000000);
define("SSNFLAG_ALL",                 0xFFFFFFFF); /* all that and a bag of chips */
define("SSNFLAG_NONE",                0x00000000); /* nothing, an MT bag of chips */

//array containing all session flags except all and none
$flag_array = array("SSNFLAG_SEEN_CLIENT" => SSNFLAG_SEEN_CLIENT,
                    //"SSNFLAG_SEEN_SENDER" => SSNFLAG_SEEN_SENDER,
                    "SSNFLAG_SEEN_SERVER" => SSNFLAG_SEEN_SERVER,
                    //"SSNFLAG_SEEN_RESPONDER" => SSNFLAG_SEEN_RESPONDER,
                    "SSNFLAG_ESTABLISHED" => SSNFLAG_ESTABLISHED,
                    "SSNFLAG_NMAP" => SSNFLAG_NMAP,
                    "SSNFLAG_ECN_CLIENT_QUERY" => SSNFLAG_ECN_CLIENT_QUERY,
                    "SSNFLAG_ECN_SERVER_REPLY" => SSNFLAG_ECN_SERVER_REPLY,
                    "SSNFLAG_HTTP_1_1" => SSNFLAG_HTTP_1_1,
                    "SSNFLAG_SEEN_PMATCH" => SSNFLAG_SEEN_PMATCH,
                    "SSNFLAG_MIDSTREAM" => SSNFLAG_MIDSTREAM,
                    "SSNFLAG_CLIENT_FIN" => SSNFLAG_CLIENT_FIN,
                    "SSNFLAG_SERVER_FIN" => SSNFLAG_SERVER_FIN,
                    "SSNFLAG_CLIENT_PKT" => SSNFLAG_CLIENT_PKT,
                    "SSNFLAG_SERVER_PKT" => SSNFLAG_SERVER_PKT,
                    "SSNFLAG_COUNTED_INITIALIZE" => SSNFLAG_COUNTED_INITIALIZE,
                    "SSNFLAG_COUNTED_ESTABLISH" => SSNFLAG_COUNTED_ESTABLISH,
                    "SSNFLAG_COUNTED_CLOSING" => SSNFLAG_COUNTED_CLOSING,
                    "SSNFLAG_TIMEDOUT" => SSNFLAG_TIMEDOUT,
                    "SSNFLAG_PRUNED" => SSNFLAG_PRUNED,
                    "SSNFLAG_RESET" => SSNFLAG_RESET,
                    "SSNFLAG_DROP_CLIENT" => SSNFLAG_DROP_CLIENT,
                    "SSNFLAG_DROP_SERVER" => SSNFLAG_DROP_SERVER,
                    "SSNFLAG_LOGGED_QUEUE_FULL" => SSNFLAG_LOGGED_QUEUE_FULL,
                    "SSNFLAG_STREAM_ORDER_BAD" => SSNFLAG_STREAM_ORDER_BAD,
                    "SSNFLAG_FORCE_BLOCK" => SSNFLAG_FORCE_BLOCK,
                    "SSNFLAG_CLIENT_SWAP" => SSNFLAG_CLIENT_SWAP,
                    "SSNFLAG_CLIENT_SWAPPED" => SSNFLAG_CLIENT_SWAPPED);

/*********************************END SESSION FLAGS**********************************************/

/*
 * Maps
 */
 //Stream5 Stat
//set all defaults 
$a0 = $b0 = $c0 = $d0 = $e0 = $f0 = $g0 = $h0 = $i0 = $j0 = "0";
$a1 = $b1 = $c1 = $d1 = $e1 = $f1 = $g1 = $h1 = $i1 = $j1 = "|";
$a2 = $b2 = $c2 = $d2 = $e2 = $f2 = $g2 = $h2 = $i2 = $j2 = "+";
$a3 = $b3 = $c3 = $d3 = $e3 = $f3 = $g3 = $h3 = $i3 = $j3 = "-";
$z = "0";
$stream5_state_syn  = "STREAM5_STATE_SYN";
$stream5_state_syn_ack = "STREAM5_STATE_SYN_ACK";
$stream5_state_ack = "STREAM5_STATE_ACK";
$stream5_state_established = "STREAM5_STATE_ESTABLISHED";
$stream5_state_drop_client = "STREAM5_STATE_DROP_CLIENT";
$stream5_state_drop_server = "STREAM5_STATE_DROP_SERVER";//$colors->getColoredString("STREAM5_STATE_DROP_SERVER", "dark_gray");
$stream5_state_midstream = "STREAM5_STATE_MIDSTREAM";
$stream5_state_timedout = "STREAM5_STATE_TIMEDOUT";
$stream5_state_unreach = "STREAM5_STATE_UNREACH";
$stream5_state_closed = "STREAM5_STATE_CLOSED";
$stream5_state_none = "STREAM5_STATE_NONE";


$stream5_state_map_reference = array(
    "STREAM5_STATE_SYN"         => array('map_letter' => 'a', 'map_var' => 'stream5_state_syn'),
    "STREAM5_STATE_SYN_ACK"     => array('map_letter' => 'b', 'map_var' => 'stream5_state_syn_ack'),
    "STREAM5_STATE_ACK"         => array('map_letter' => 'c', 'map_var' => 'stream5_state_ack'),
    "STREAM5_STATE_ESTABLISHED" => array('map_letter' => 'd', 'map_var' => 'stream5_state_established'),
    "STREAM5_STATE_DROP_CLIENT" => array('map_letter' => 'e', 'map_var' => 'stream5_state_drop_client'),
    "STREAM5_STATE_DROP_SERVER" => array('map_letter' => 'f', 'map_var' => 'stream5_state_drop_server'),
    "STREAM5_STATE_MIDSTREAM"   => array('map_letter' => 'g', 'map_var' => 'stream5_state_midstream'),
    "STREAM5_STATE_TIMEDOUT"    => array('map_letter' => 'h', 'map_var' => 'stream5_state_timedout'),
    "STREAM5_STATE_UNREACH"     => array('map_letter' => 'i', 'map_var' => 'stream5_state_unreach'),
    "STREAM5_STATE_CLOSED"      => array('map_letter' => 'j', 'map_var' => 'stream5_state_closed'),
    );
    
$stream5_state_map_header = $colors->getColoredString(
        "\n+==================+ Stream5 State Map +==============-====+  \n\n", "white", "black");

$stream5_state_map = "";
//redefineMap("state");

//Session Flag Map 
//define the rest of the map.  a - j will be re-used for this map
$k0 = $l0 = $m0 = $n0 = $o0 = $p0 = $q0 = $r0 = $s0 = $t0 = $u0 = $v0 = $w0 = $x0 = $y0 = $z0 = "0";
$k1 = $l1 = $m1 = $n1 = $o1 = $p1 = $q1 = $r1 = $s1 = $t1 = $u1 = $v1 = $w1 = $x1 = $y1 = $z1 = "|";
$k2 = $l2 = $m2 = $n2 = $o2 = $p2 = $q2 = $r2 = $s2 = $t2 = $u2 = $v2 = $w2 = $x2 = $y2 = $z2 = "+";
$k3 = $l3 = $m3 = $n3 = $o3 = $p3 = $q3 = $r3 = $s3 = $t3 = $u3 = $v3 = $w3 = $x3 = $y3 = $z3 = "-";

$sfsc = "SSNFLAG_SEEN_CLIENT";
$sfssrv = "SSNFLAG_SEEN_SERVER";
$sfe = "SSNFLAG_ESTABLISHED";
$sfnmap = "SSNFLAG_NMAP";
$sfecq = "SSNFLAG_ECN_CLIENT_QUERY";
$sfesr = "SSNFLAG_ECN_SERVER_REPLY";
$sfhttp = "SSNFLAG_HTTP_1_1";
$sfspmat = "SSNFLAG_SEEN_PMATCH";
$sfm = "SSNFLAG_MIDSTREAM";
$sfcf = "SSNFLAG_CLIENT_FIN";
$sfsf = "SSNFLAG_SERVER_FIN";
$sfcp = "SSNFLAG_CLIENT_PKT";
$sfsp = "SSNFLAG_SERVER_PKT";
$sfci = "SSNFLAG_COUNTED_INITIALIZE";
$sfce = "SSNFLAG_COUNTED_ESTABLISH";
$sfcc = "SSNFLAG_COUNTED_CLOSING";
$sft = "SSNFLAG_TIMEDOUT";
$sfp = "SSNFLAG_PRUNED";
$sfr = "SSNFLAG_RESET";
$sfdc = "SSNFLAG_DROP_CLIENT";
$sfds = "SSNFLAG_DROP_SERVER";
$sflqf = "SSNFLAG_LOGGED_QUEUE_FULL";
$sfsob = "SSNFLAG_STREAM_ORDER_BAD";
$sffb = "SSNFLAG_FORCE_BLOCK";
$sfcs = "SSNFLAG_CLIENT_SWAP";
$sfcsd = "SSNFLAG_CLIENT_SWAPPED";
      
$session_flag_map_reference = array(
    "SSNFLAG_SEEN_CLIENT"        => array('map_letter' => 'a', 'map_var' => 'sfsc'),
    "SSNFLAG_SEEN_SERVER"        => array('map_letter' => 'b', 'map_var' => 'sfssrv'),
    "SSNFLAG_ESTABLISHED"        => array('map_letter' => 'c', 'map_var' => 'sfe'),
    "SSNFLAG_NMAP"               => array('map_letter' => 'd', 'map_var' => 'sfnmap'),
    "SSNFLAG_ECN_CLIENT_QUERY"   => array('map_letter' => 'e', 'map_var' => 'sfecq'),
    "SSNFLAG_ECN_SERVER_REPLY"   => array('map_letter' => 'f', 'map_var' => 'sfesr'),
    "SSNFLAG_HTTP_1_1"           => array('map_letter' => 'g', 'map_var' => 'sfhttp'),
    "SSNFLAG_SEEN_PMATCH"        => array('map_letter' => 'h', 'map_var' => 'sfspmat'),
    "SSNFLAG_MIDSTREAM"          => array('map_letter' => 'i', 'map_var' => 'sfm'),
    "SSNFLAG_CLIENT_FIN"         => array('map_letter' => 'j', 'map_var' => 'sfcf'),
    "SSNFLAG_SERVER_FIN"         => array('map_letter' => 'k', 'map_var' => 'sfsf'),
    "SSNFLAG_CLIENT_PKT"         => array('map_letter' => 'l', 'map_var' => 'sfcp'),
    "SSNFLAG_SERVER_PKT"         => array('map_letter' => 'm', 'map_var' => 'sfsf'),
    "SSNFLAG_COUNTED_INITIALIZE" => array('map_letter' => 'n', 'map_var' => 'sfci'),
    "SSNFLAG_COUNTED_ESTABLISH"  => array('map_letter' => 'o', 'map_var' => 'sfce'),
    "SSNFLAG_COUNTED_CLOSING"    => array('map_letter' => 'p', 'map_var' => 'sfcc'),
    "SSNFLAG_TIMEDOUT"           => array('map_letter' => 'q', 'map_var' => 'sft'),
    "SSNFLAG_PRUNED"             => array('map_letter' => 'r', 'map_var' => 'sfp'),
    "SSNFLAG_RESET"              => array('map_letter' => 's', 'map_var' => 'sfr'),
    "SSNFLAG_DROP_CLIENT"        => array('map_letter' => 't', 'map_var' => 'sfdc'),
    "SSNFLAG_DROP_SERVER"        => array('map_letter' => 'u', 'map_var' => 'sfds'),
    "SSNFLAG_LOGGED_QUEUE_FULL"  => array('map_letter' => 'v', 'map_var' => 'sflqf'),
    "SSNFLAG_STREAM_ORDER_BAD"   => array('map_letter' => 'w', 'map_var' => 'sfsob'),
    "SSNFLAG_FORCE_BLOCK"        => array('map_letter' => 'x', 'map_var' => 'sffb'),
    "SSNFLAG_CLIENT_SWAP"        => array('map_letter' => 'y', 'map_var' => 'sfcs'),
    "SSNFLAG_CLIENT_SWAPPED"     => array('map_letter' => 'z', 'map_var' => 'sfcsd')
    );     
$session_flag_map_header = $colors->getColoredString(
        "\n+==================+ Session Flag Map +==================+  \n\n", "white", "black");
               
$session_flag_map = "";
//redefineMap("flag");
                
/********************************End Maps***************************************************/ 
$silent = FALSE;
$all_data = FALSE;
$print_script_use = FALSE;
/**********************************End Global Variables*********************************************/         
                  
/*
 * Set/Get/Check Options
 */ 

$shortopts = "m:hs";
$longopts = array(
    "csv:", //accepts a files and creates a csv
    "help", //print help message
    "LWstate:", //accepts state hex value and prints the map
    "LWFlags:", //accepts a flag hex value and prints the map
    "summary:", //accepts a csv file and prints a summary of the stats
    "limit:", //sets the limit for number of hosts to output
    "all-data", //pulls stats from all available lines, default will only pull prunes
    "script-stats" //print stats of script (off by default)
    );
$options = getopt($shortopts, $longopts);
if(count($options) > 0) {
    if (!is_array($options) ) {
        print "There was a problem reading in the options.\n\n";
        exit(1);
    } 
    if(array_key_exists("h", $options) || array_key_exists('help', $options)) {
        printHelp();
        exit(0);
    }
    if(array_key_exists("script-stats", $options)) {
        $print_script_use = TRUE;
    }
    if(array_key_exists("s", $options)) {
        $silent = TRUE;
    }
    else if(array_key_exists("m", $options)) {
        switch ($options["m"]) {
            case 'state':
                setMapColor("state", getStatesSet("0x8e"));
                echo 
                $stream5_state_map_header.
                $stream5_state_map.
                "In the example above the following session states are set:\n".
                "STREAM5_STATE_SYN_ACK\n".
                "STREAM5_STATE_ACK\n".
                "STREAM5_STATE_ESTABLISHED\n".
                "STREAM5_STATE_TIMEDOUT\n";               
                break;
            case 'flag':
                setMapColor("flag", getFlagsSet("0xe"));
                echo 
                $session_flag_map_header.
                $session_flag_map;
                break;
            default:
                echo "No valid map type given! Valid types are 'state' and 'flag'\n";
                printHelp();
                break;
        }
        exit(0);
    }
    if(array_key_exists("LWstate", $options) || array_key_exists("LWFlags", $options)) {
        if(array_key_exists("LWstate", $options)) {
            if(!isValidHexString($options["LWstate"])) {
                echo "The string '" . $options["LWstate"] ."' contains non-hex values. This must be hex values only! The leading 0x is optional.\n";
                exit(0);
            }
            
            $binary_state = base_convert($options["LWstate"], 16, 2);
            $formated_state = "    binary: " . formatBinaryString($binary_state, "state") . "\n\n";
             
            setMapColor("state", getStatesSet($options["LWstate"]));
            redefineMap("state");
            //print map
            echo $stream5_state_map_header . 
                "\thex: " . $options["LWstate"] . "\n" .
                $formated_state .
                $stream5_state_map;
        } 
        if(array_key_exists("LWFlags", $options)) {
            if(!isValidHexString($options["LWFlags"])) {
                echo "The string '" . $options["LWFlags"] ."' contains non-hex values. This must be hex values only! The leading 0x is optional.\n";
                exit(0);
            }
            
            $binary_state = base_convert($options["LWFlags"], 16, 2);
            $formated_state = "    binary: " . formatBinaryString($binary_state, "flag") . "\n\n";
            setMapColor("flag", getFlagsSet($options["LWFlags"]));
            redefineMap("flag");
            echo $session_flag_map_header . 
                "\thex: " . $options["LWFlags"] . "\n" .
                $formated_state .
                $session_flag_map;
        }
        exit(0); 
    }
    else if (array_key_exists("csv", $options)){
        /*echo "csv files: " . $options['csv'] . "\n";
        exit(0);*/
        if(array_key_exists("all-data", $options)) {
            $all_data = TRUE;
        }
        $start_time = time();
        generateCSV($options["csv"]);
        if($print_script_use)
            echo "\nRun time: " . getRunTime($start_time);
    }
    else if (array_key_exists("summary", $options)){
        if(array_key_exists("limit", $options)){
            if((string)(int)$options['limit'] == $options['limit'])
                $limit = $options['limit'];
            else {
                echo "The limit parameter must be an integer! '" . $options['limit'] ."' was given\.n";
                printHelp();
                exit(0);
            }
        }
        else 
            $limit = 50;
        $start_time = time();
        getSummaryStats($options["summary"], $limit);
        if($print_script_use)
            echo "\nRun time: " . getRunTime($start_time);
    }
}
else {
    printHelp();
    exit(0);
}
/************************End Options*************************************/
if($print_script_use)
    echo "peak memory use: " . memory_get_peak_usage() . " bytes\n";
/*
 * Functions 
 */
function printHelp() {
    global $VERSION;
    echo "getS5HostInfo.php\n\n" .
    "Version $VERSION\n" .
    "Usage: getS5HostInfo [options] [--] [args...] <file> \n\n" .
    "This script accepts a syslog (messages) file and prints information about stream5 sessions.\n".
    "This version of the script was written based on open source snort version 2.9.6.\n\n" .
    "Options:\n" .
    "\t--csv <filename>\tGet all S5 info from a syslog file and create a csv file.\n" .
    "\t-h --help\t\tThis help\n" .
    "\t--limit <limit>\t\tSet the limit for the number of sessions/hosts to display in the summary (useless without --summary). (default is 50)\n" .
    "\t--LWFlags <hex>\t\tPrint the session flag map for the given hex string. The leading 0x is optional. Max 32 bit hex string accepted.\n" .
    "\t--LWstate <hex>\t\tPrint the stream5 state map for the given hex string. The leading 0x is optional. Max 16 bit hex string accepted.\n" .
    "\t-m state|flag\t\tPrints the mapping of the stream5 states or flags\n" .
    "\t-s\t\t\tSilent mode. Will not output summaries to screen.\n" .
    "\t--summary <csv_file>\tPrint the summary of stats contained within a csv file. CSV must have been created by this script, or in the same format.\n".
    "\t--all-data \t\tPull stats from all S5 messages. By default it will only pull data from S5 prunes. (meaningless without --csv)\n".
    "\t--script-stats \t\tPrint stats for script. i.e. memory use and runtime.\n".
    "\n";
}

function isValidHexString($hex_string) {
    $hex_check = strtolower($hex_string);
    if(substr($hex_check, 0, 2) == "0x")//if 0x is provided ignore first 2 in checking for valid values
        $hex_check = substr($hex_check, 2);
    if(!ctype_xdigit($hex_check)) 
        return FALSE;
    else 
        return TRUE;
}

function formatBinaryString($binary, $type) {
    $binary_string = trim((string)$binary);
    $length = strlen($binary_string);
    
    switch ($type) {
    	case 'state': //should return formated 16 bit string as 0000000 00000000
    	    if($length > 16) { //exit if more than 16 charaters
    	        echo "state should only be 16 bits at most but it is $length bits!\n";
    	        exit(1);
    	    }
    	    
    	    $zeros_to_add = 16 - $length;
            $full_string = str_repeat("0", $zeros_to_add) . $binary_string;
            return substr($full_string, 0, 8) . " " . substr($full_string, 8);
    		break;
    	
        case 'flag': //should return formated 16 bit string as 0000000 00000000
            if($length > 32) { //exit if more than 16 charaters
                echo "flag should only be 32 bits at most but it is $length bits!\n";
                exit(1);
            }
            
            $zeros_to_add = 32 - $length;
            $full_string = str_repeat("0", $zeros_to_add) . $binary_string;
            return substr($full_string, 0, 8) . " " . substr($full_string, 8, 8) . " " . 
                   substr($full_string, 16, 8) . " " . substr($full_string, 24);
            break;
            
    	default:
    		echo "No case for '$type'! exiting...";
    		exit(2);
    		break;
    }
}

function printNewPercent($old_percent, $new_percent, $pre_str = "") {
    $bs = str_repeat("\x08", strlen($old_percent)) . "\x08";
    $bs .= str_repeat("\x08", strlen($pre_str));
    echo "$bs$pre_str$new_percent%" ;
}
function printStateDetails() {
    
}

function printFlagDetails() {
    
}

function getSummaryStats($file, $limit = 50) {
    global $colors, $silent;
    $total_lines = getLineCount($file);
    $mod_val = intval($total_lines/100);
    $cur_percent = "0";
    $percent_str = "Percent Lines Read: ";
    echo "Reading file $file\n".
         "$percent_str$cur_percent%";
    //$start_time = microtime();
    global $state_array, $flag_array, $csv_header;
    $top_count = $limit;
    //stream5 counters
    $s5_state_counters = $state_array;
    unset($s5_state_counters["STREAM5_STATE_SYN"], $s5_state_counters["STREAM5_STATE_SYN_ACK"], $s5_state_counters["STREAM5_STATE_ACK"]);
    foreach ($s5_state_counters as $key => $value) {
        $s5_state_counters[$key] = 0;
    }
    
    //session counters
    $ssn_flag_counters = $flag_array;
    unset($ssn_flag_counters["SSNFLAG_SEEN_CLIENT"], $ssn_flag_counters["SSNFLAG_SEEN_SENDER"],
          $ssn_flag_counters["SSNFLAG_SEEN_SERVER"], $ssn_flag_counters["SSNFLAG_SEEN_RESPONDER"]);
    foreach ($ssn_flag_counters as $key => $value) {
        $ssn_flag_counters[$key] = 0;
    }

    //special counters
    $client_no_server_count = $server_no_client_count = $s5_drop_both = 0;
    $syn_no_syn_ack = $syn_ack_no_syn = $saw_3w_hs = 0;
    $both_c_and_s = $both_s_and_sa = 0;
    $total = 0;
    
    //IP and port counters
    $source_ports = $dest_ports = $host_hash_counters = $app_proto_ids = array();
    
    //output sumamry strings
    $first_date = $last_date = ""; 
    $low_time = $high_time = 0;
    $snrt1 = " ,,_  "; $srev1 = strrev($snrt1);
    $snrt2 = 'o"  )~'; $srev2 = '~(  "o';
    $snrt3 = " '''' "; $srev3 = strrev($snrt3);
    $snrt4 = $colors->getColoredString($snrt1, "dark_gray");
    $snrt5 = $colors->getColoredString($snrt2, "dark_gray");
    $snrt6 = $colors->getColoredString($snrt3, "dark_gray");
    $file_handle = fopen($file, "r");
    if ($file_handle) {
        $line = fgets($file_handle);
        if($csv_header != trim($line)) {
            echo "\nUnexpected header for csv file $file.  Make sure that this csv was generated by getS5HostInfo.\n" . 
            "Expected header:\n$csv_header\n" .
            "First line (header):\n$line\n";
            exit(1);
        }
        $linehold = $line = fgets($file_handle);
        $low_time = intval(substr($line, 0, strpos($line, ",")));
        while (!feof($file_handle))
        {
            $total++;
            if($total % $mod_val == 0) {
                $new_percent = $cur_percent + 1; 
                printNewPercent($cur_percent++, $new_percent, $percent_str);
            }
            $csv_array = explode(",", $line);
            if(count($csv_array) < 20)
                echo "Not enough entries for line: $line\n";
            else if($csv_array[0] === "timestamp")
                echo "\nSkipping line $line\n"; 
            else {
                //check times
                if(intval($csv_array[0]) < $low_time)
                    $low_time = intval($csv_array[0]);
                if(intval($csv_array[0]) > $high_time)
                    $high_time = intval($csv_array[0]);
                //get host info
                $srcIP = $csv_array[2];
                $srcPort = $csv_array[3];
                $dstIP = $csv_array[4];
                $dstPort = $csv_array[5];
                $ip_key = "$srcIP+$dstIP";
                
                //set ports and appProtos
                $app_proto_ids[$csv_array[6]] += 1;
                $source_ports[$srcPort] += 1;
                $dest_ports[$dstPort] += 1;
                
                //set stream5 global counters
                $s5ss = $csv_array[8];
                $s5ssa = $csv_array[9];
                $s5sa = $csv_array[10];
                $s5_state_counters["STREAM5_STATE_ESTABLISHED"] += $csv_array[11];
                $s5_state_counters["STREAM5_STATE_DROP_CLIENT"] += $csv_array[12];
                $s5_state_counters["STREAM5_STATE_DROP_SERVER"] += $csv_array[13];
                $s5_drop_both += ($csv_array[12] + $csv_array[13] == 2 ? 1 : 0);
                $s5_state_counters["STREAM5_STATE_MIDSTREAM"] += $csv_array[14];
                $s5_state_counters["STREAM5_STATE_TIMEDOUT"] += $csv_array[15];
                $s5_state_counters["STREAM5_STATE_UNREACH"] += $csv_array[16];
                $s5_state_counters["STREAM5_STATE_CLOSED"] += $csv_array[17];
                
                //set session global counters
                $sfsc = $csv_array[18];
                $sfssrv = $csv_array[19];
                $ssn_flag_counters["SSNFLAG_ESTABLISHED"] += $csv_array[20];
                $ssn_flag_counters["SSNFLAG_NMAP"] += $csv_array[21];
                $ssn_flag_counters["SSNFLAG_ECN_CLIENT_QUERY"] += $csv_array[22];
                $ssn_flag_counters["SSNFLAG_ECN_SERVER_REPLY"] += $csv_array[23];
                $ssn_flag_counters["SSNFLAG_HTTP_1_1"] += $csv_array[24];
                $ssn_flag_counters["SSNFLAG_SEEN_PMATCH"] += $csv_array[25];
                $ssn_flag_counters["SSNFLAG_MIDSTREAM"] += $csv_array[26];
                $ssn_flag_counters["SSNFLAG_CLIENT_FIN"] += $csv_array[27];
                $ssn_flag_counters["SSNFLAG_SERVER_FIN"] += $csv_array[28];
                $ssn_flag_counters["SSNFLAG_CLIENT_PKT"] += $csv_array[29];
                $ssn_flag_counters["SSNFLAG_SERVER_PKT"] += $csv_array[30];
                $ssn_flag_counters["SSNFLAG_COUNTED_INITIALIZE"] += $csv_array[31];
                $ssn_flag_counters["SSNFLAG_COUNTED_ESTABLISH"] += $csv_array[32];
                $ssn_flag_counters["SSNFLAG_COUNTED_CLOSING"] += $csv_array[33];
                $ssn_flag_counters["SSNFLAG_TIMEDOUT"] += $csv_array[34];
                $ssn_flag_counters["SSNFLAG_PRUNED"] += $csv_array[35];
                $ssn_flag_counters["SSNFLAG_RESET"] += $csv_array[36];
                $ssn_flag_counters["SSNFLAG_DROP_CLIENT"] += $csv_array[37];
                $ssn_flag_counters["SSNFLAG_DROP_SERVER"] += $csv_array[38];
                $ssn_flag_counters["SSNFLAG_LOGGED_QUEUE_FULL"] += $csv_array[39];
                $ssn_flag_counters["SSNFLAG_STREAM_ORDER_BAD"] += $csv_array[40];
                $ssn_flag_counters["SSNFLAG_FORCE_BLOCK"] += $csv_array[41];
                $ssn_flag_counters["SSNFLAG_CLIENT_SWAP"] += $csv_array[42];
                $ssn_flag_counters["SSNFLAG_CLIENT_SWAPPED"] += $csv_array[43];
                
                //set stream5 ip counters
                $host_hash_counters[$ip_key]["STREAM5_STATE_ESTABLISHED"] += $csv_array[11];
                $host_hash_counters[$ip_key]["STREAM5_STATE_DROP_CLIENT"] += $csv_array[12];
                $host_hash_counters[$ip_key]["STREAM5_STATE_DROP_SERVER"] += $csv_array[13];
                $host_hash_counters[$ip_key]["s5_drop_both"] += ($csv_array[12] + $csv_array[13] == 2 ? 1 : 0);
                $host_hash_counters[$ip_key]["STREAM5_STATE_MIDSTREAM"] += $csv_array[14];
                $host_hash_counters[$ip_key]["STREAM5_STATE_TIMEDOUT"] += $csv_array[15];
                $host_hash_counters[$ip_key]["STREAM5_STATE_UNREACH"] += $csv_array[16];
                $host_hash_counters[$ip_key]["STREAM5_STATE_CLOSED"] += $csv_array[17];
                
                //set session ip counters
                $host_hash_counters[$ip_key]["SSNFLAG_ESTABLISHED"] += $csv_array[20];
                $host_hash_counters[$ip_key]["SSNFLAG_NMAP"] += $csv_array[21];
                $host_hash_counters[$ip_key]["SSNFLAG_ECN_CLIENT_QUERY"] += $csv_array[22];
                $host_hash_counters[$ip_key]["SSNFLAG_ECN_SERVER_REPLY"] += $csv_array[23];
                $host_hash_counters[$ip_key]["SSNFLAG_HTTP_1_1"] += $csv_array[24];
                $host_hash_counters[$ip_key]["SSNFLAG_SEEN_PMATCH"] += $csv_array[25];
                $host_hash_counters[$ip_key]["SSNFLAG_MIDSTREAM"] += $csv_array[26];
                $host_hash_counters[$ip_key]["SSNFLAG_CLIENT_FIN"] += $csv_array[27];
                $host_hash_counters[$ip_key]["SSNFLAG_SERVER_FIN"] += $csv_array[28];
                $host_hash_counters[$ip_key]["SSNFLAG_CLIENT_PKT"] += $csv_array[29];
                $host_hash_counters[$ip_key]["SSNFLAG_SERVER_PKT"] += $csv_array[30];
                $host_hash_counters[$ip_key]["SSNFLAG_COUNTED_INITIALIZE"] += $csv_array[31];
                $host_hash_counters[$ip_key]["SSNFLAG_COUNTED_ESTABLISH"] += $csv_array[32];
                $host_hash_counters[$ip_key]["SSNFLAG_COUNTED_CLOSING"] += $csv_array[33];
                $host_hash_counters[$ip_key]["SSNFLAG_TIMEDOUT"] += $csv_array[34];
                $host_hash_counters[$ip_key]["SSNFLAG_PRUNED"] += $csv_array[35];
                $host_hash_counters[$ip_key]["SSNFLAG_RESET"] += $csv_array[36];
                $host_hash_counters[$ip_key]["SSNFLAG_DROP_CLIENT"] += $csv_array[37];
                $host_hash_counters[$ip_key]["SSNFLAG_DROP_SERVER"] += $csv_array[38];
                $host_hash_counters[$ip_key]["SSNFLAG_LOGGED_QUEUE_FULL"] += $csv_array[39];
                $host_hash_counters[$ip_key]["SSNFLAG_STREAM_ORDER_BAD"] += $csv_array[40];
                $host_hash_counters[$ip_key]["SSNFLAG_FORCE_BLOCK"] += $csv_array[41];
                $host_hash_counters[$ip_key]["SSNFLAG_CLIENT_SWAP"] += $csv_array[42];
                $host_hash_counters[$ip_key]["SSNFLAG_CLIENT_SWAPPED"] += $csv_array[43];
                
                //Set special counters
                if($s5ss && !$s5ssa) { //seen syn but not syn_ack
                    $syn_no_syn_ack++;
                    $host_hash_counters[$ip_key]['syn_no_syn_ack']++;
                }
                else if(!$s5ss && $s5ssa) { //seen syn but not syn_ack
                    $syn_ack_no_syn++;
                    $host_hash_counters[$ip_key]['syn_ack_no_syn']++;
                }
                else if($s5ss && $s5ssa) {//seen both
                    $both_s_and_sa++;
                    //$host_hash_counters[$ip_key]['both_s_and_sa']++;
                    if($s5sa) {//saw 3 way handshake
                        $saw_3w_hs++;
                        //$host_hash_counters[$ip_key]['saw_3w_hs']++;
                    }
                }
                
                if($sfsc && !$sfssrv) { //seen client but not server
                    $client_no_server_count++;
                    $host_hash_counters[$ip_key]['client_no_server_count']++;
                }
                else if(!$sfsc && $sfssrv) { //seen server but not client
                    $server_no_client_count++;
                    $host_hash_counters[$ip_key]['server_no_client_count']++;
                }
                else if ($sfsc && $sfssrv) {
                    $both_c_and_s++;
                    $host_hash_counters[$ip_key]['both_c_and_s']++;
                }
            }
            $linehold = $line;
            $line = fgets($file_handle);
        }
        printNewPercent($cur_percent, "100", $percent_str);
        echo "\n";
        $file_out = "summary-" . uniqid();
        echo "Outputting to file $file_out\n";
        $out_file_handle = fopen($file_out, "w");
        
        printTopSorted($host_hash_counters, 'syn_no_syn_ack', $top_count);
        printTopSorted($host_hash_counters, 'syn_ack_no_syn', $top_count, $out_file_handle);
        printTopSorted($host_hash_counters, 'client_no_server_count', $top_count, $out_file_handle);
        printTopSorted($host_hash_counters, 'server_no_client_count', $top_count, $out_file_handle);
        $sorted = arsort($source_ports);
        printSortedArray($source_ports, "Port", "Times Seen", 15, "Top Source ports seen:", $out_file_handle);
        $sorted = arsort($dest_ports);
        printSortedArray($dest_ports, "Port", "Times Seen", 15, "Top Dest ports seen:", $out_file_handle);
        unset($app_proto_ids["-1"]);
        $sorted = arsort($app_proto_ids);
        printSortedArray($app_proto_ids, "AppID", "Times Seen", 15, "Top Application Protocols Seen:", $out_file_handle);
        
        $first_date = date("Y-m-d H:i:s", $low_time);
        $last_date = date("Y-m-d H:i:s", $high_time);
        
        $percent_cns = intval($client_no_server_count/$total*100);
        $percent_cns = ($percent_cns >= 50 ? $colors->getColoredString($percent_cns."%", "red") : $percent_cns."%");
        
        $percent_snc = intval($server_no_client_count/$total*100);
        $percent_snc = ($percent_snc >= 50 ? $colors->getColoredString($percent_snc."%", "red") : $percent_snc."%");
        
        $percent_snsa = intval($syn_no_syn_ack/$total*100);
        $percent_snsa = ($percent_snsa >= 50 ? $colors->getColoredString($percent_snsa."%", "red") : $percent_snsa."%");
        
        $percent_sans = intval($syn_ack_no_syn/$total*100);
        $percent_sans = ($percent_sans >= 50 ? $colors->getColoredString($percent_sans."%", "red") : $percent_sans."%");
        
        $percent_bcs = intval($both_c_and_s/$total*100);
        $percent_bcs = ($percent_bcs < 50 ? $colors->getColoredString($percent_bcs."%", "red") : $percent_bcs."%");
        
        $percent_bssa = intval($both_s_and_sa/$total*100);
        $percent_bssa = ($percent_bssa < 50 ? $colors->getColoredString($percent_bssa."%", "red") : $percent_bssa."%");
        
        $percent_3whs = intval($saw_3w_hs/$total*100);
        
  $output .= "=========================================\n" .
             "| $snrt1                         $srev1 |\n" .
             "| $snrt2  Stream5 State Summary  $srev2 |\n" .
             "| $snrt3                         $srev3 |\n" .
             "=========================================\n" .
             "Time: $first_date - $last_date\n" .
             "Total Sessions           :  $total\n" .
             "Saw Client but not Server:  $client_no_server_count ($percent_cns)\n" .
             "Saw Server but not Client:  $server_no_client_count ($percent_snc)\n" .
             "Saw Client and Server    :  $both_c_and_s ($percent_bcs)\n";
             foreach ($s5_state_counters as $key => $value) {
                 $output .= sprintf("%-25s:  %d (%.2f%%)\n", $key, $value, $value/$total*100);
             }
        $output .=
           "\n=========================================\n" .
             "| $snrt1                         $srev1 |\n" .
             "| $snrt2  Session Flags Summary  $srev2 |\n" .
             "| $snrt3                         $srev3 |\n" .
             "=========================================\n" .
             "Time: $first_date - $last_date\n" .
             "Total Sessions            :  $total\n" .
             "Saw SYN but not SYN_ACK   :  $syn_no_syn_ack ($percent_snsa)\n" .
             "Saw SYN_ACK but not SYN   :  $syn_ack_no_syn ($percent_sans)\n" .
             "Saw SYN and SYN_ACK       :  $both_s_and_sa ($percent_bssa)\n". 
             "Saw 3-Way Handshake       :  $saw_3w_hs ($percent_3whs%)\n";
             foreach ($ssn_flag_counters as $key => $value) {
                 $output .= sprintf("%-26s:  %d (%.2f%%)\n", $key, $value, $value/$total*100);
             }
             fwrite($out_file_handle, $output);
             if(!$silent)
                echo $output;
             echo "\nOutput summary file: '$file_out'.\n";
    }
    else {
        echo "Unable to open file $file!\n";
        exit(1);
    }
}

function printTopSorted($sort_array, $key, $limit, $out_file_handle = NULL) {
    global $sort_key, $silent;
    //syn not syn ack
    $sort_key = $key;
    $sorted = $sort_array;
    $output = "";
    if(!uasort($sorted, "cmpVals")) 
        $output .= "Unable to sort with key '$sort_key'! Results for this will not be correct.\n";
    $i = $j = 0;
    $output .= "Top $limit sessions for $sort_key:\n";
    $val_hold = -1;
    if(count($sort_array) < 1)
        $output .= "None";
    foreach ($sorted as $key => $value) {
        //This can be changed to be configurable if needed:
        //to count values that are the same as one number (don't increment) 
        //$j++;
        /*if($value[$sort_key] != $val_hold) {
            $i++;
            $val_hold = $value[$sort_key];
        }
        else {
        	echo "no match on arr: '" . $value[$sort_key] ."' and hold '$val_hold'\n";
        }*/ 
        if($value[$sort_key] == 0 || $value[$sort_key] == NULL){
            if($i == 0){
                $output .= "None";
            }
            break;
        }
        $i++;
        $key_array = explode("+", $key);
        $src_dest = sprintf("%-2d) %-15s -> %-15s", $i, $key_array[0],$key_array[1]);
        $output .= "$src_dest : " . $value[$sort_key] . "\n";
        if($i >= $limit/* || $j >= 100*/)
            break;
    }
    $output .= "\n\n";
    if($out_file_handle != NULL)
        fwrite($out_file_handle, $output);
    else if($silent){
        echo "No output file, and silent was passed, outputting to screen anyway!\n";
        $silent = FALSE;
    }
    if(!$silent)
        echo $output;
    return 1;
}

function printSortedArray($sorted_array, $key, $value, $limit, $header = "", $out_file_handle = NULL){
    global $silent;
    $output = "$header\n$key : $value\n";
    $i = 0;
    if(count($sorted_array) < 1)
        $output .= "None";
    foreach ($sorted_array as $key => $value) {
        if($value == 0 || $value == NULL){
            if($i == 0){
                $output .= "None";
            }
            break;
        }
        $i++;
        $output .= sprintf("%-2d) %-8s : %d\n", $i, $key, $value);
        if($i >= $limit)
            break;
    }
    $output .= "\n\n";
    if($out_file_handle != NULL)
        fwrite($out_file_handle, $output);
    else if($silent){
        echo "No output file, and silent was passed, outputting to screen anyway!\n";
        $silent = FALSE;
    }
    if(!$silent)
        echo $output;
    return 1;
}

/**
 * Accepts 2 associative arrays of sessions and compares the values
 * based off of the global sort_key.
 */
function cmpVals($a, $b) {
    global $sort_key;//using this as global now until I can figure out how to use closures properly with usort
    if($sort_key == ""){
        echo "Unable to sort, the sort_key is undefined!\n";
        exit(0);
    }
    if ($a[$sort_key] == $b[$sort_key]) {
        return 0;
    }
    return ($a[$sort_key] < $b[$sort_key]) ? 1 : -1;
}

function flagIsSet($flag_hex, $flag) {
    /*DEBUG
    $format = 'flags:        %1$032b' . "\n" . 
              'compare flag: %2$032b' . "\n" .
              'result:       %3$032b' . "\n";
    $result = $flag_hex & $flag; 
    printf($format, $flag_hex, $flag, $result); 
    /*END DEBUG*/
    return $flag_hex & $flag;
}

/**
 * Accepts an epoch string and returns a string of the run time
 */
function getRunTime($start_time) {
    $run_time = intval(time() - $start_time);
    if($run_time < 60) {
        return "$run_time seconds\n";
    }
    else {
        $minutes = intval($run_time/60);
        $seconds = $run_time % 60;
        return "$minutes minutes $seconds seconds\n";
    }
}
function getLineCount($file) {
    $file_handle = fopen($file, "r");
    if ($file_handle) {
       $count = 0;
       echo "Checking file: $file...";
       while (!feof($file_handle))
        {
            $line = fgets($file_handle);
            $count++;
        }
        echo "done!\n";
        return $count; 
    }
    else {
        echo "Couldn't open file '$file'!\n";
        exit(0);
    }
}

/*
 * This function will generate a csv file of the stream5 session stats.
 * The CSV header is as follows:
 * timestamp,pid,srcIP,srcPort,dstIP,dstPort,appProto,<stream5 stats...>,<session flags...>
 * This will generate a csv file with the name <hostname>-<epoch_time>-S5Info-<uuid>.csv
 */ 
function generateCSV($file) {  
    global $csv_header, $all_data; 
    $total_lines = getLineCount($file);
    $mod_val = intval($total_lines/100);
    $cur_percent = "0";
    $percent_str = "Percent Done: ";
    $file_handle = fopen($file, "r");
    if ($file_handle) {
//examples of strings to parse
//Jul 30 04:45:03 DC1SFIRE3D01 snort[339]: S5: Session exceeded configured max bytes to queue 1048576 using 1049004 bytes (client queue). 172.20.175.22 40943 --> 172.20.234.45 80 (-1) : LWstate 0xf LWFlags 0x406003 
//Jul 30 04:45:03 DC1SFIRE3D01 snort[349]: S5: Pruned session from cache that was using 1106988 bytes (stale/timeout). 172.20.234.25 59944 --> 172.20.78.83 80 (-1) : LWstate 0xe LWFlags 0x61e002       
        $line = fgets($file_handle);
        //get date
        $date = strtotime(substr($line,0, 15));
        
        //gethostname
        $hostname = substr($line, 16, strpos($line," ", 17)-16);
        
        //get output file name
        $file_uuid = uniqid();
        $output_file = "$hostname-$date-S5Info-$file_uuid.csv";

        $count = $current_line = 0;
        $out_file_handle = fopen($output_file, "w");
        echo "Created output file $output_file!\n".
             "Reading file and dumping stats...This could take a few minutes depending on the file size and amount of S5 messages.\n".
             "$percent_str$cur_percent%";
        fwrite($out_file_handle, $csv_header."\n");
        $s5_pcre = "/S5: Pruned s/";
        if($all_data)
            $s5_pcre = "/S5: (Session|Pruned s)/";
        while (!feof($file_handle))
        {
            if(preg_match($s5_pcre, $line)){
                $csv_array = array();
                $csv_array["date"] = strtotime(substr($line,0, 15));
                $line_array = explode("[", $line, 2);
                $csv_array["pid"] = substr($line_array[1], 0, strpos($line_array[1], "]"));
            
                $useful = trim(substr($line_array[1], strpos($line_array[1], ").") + 2));
                //split on space for string: 172.20.175.22 40943 --> 172.20.234.45 80 (-1) : LWstate 0xf LWFlags 0x406003
                $info_array = preg_split("/\s+/", $useful);
                $csv_array["srcIP"] = $info_array[0];
                $csv_array["srcPort"] = $info_array[1];
                $csv_array["dstIP"] = $info_array[3];
                $csv_array["dstPort"] = $info_array[4];
                $csv_array["appProto"] = preg_replace("/\(|\)/", "", $info_array[5]);
                $csv_array["s5_state"] = getCSVString("state", getStatesSet($info_array[8])); //returns array of set flags
                $csv_array["ssn_flags"] = getCSVString("flags", getFlagsSet($info_array[10]));
                fwrite($out_file_handle, implode(",", $csv_array) . "\n");
                $count++;
            }
            $current_line++;
            if($current_line % $mod_val == 0) {
                $new_percent = $cur_percent + 1; 
                printNewPercent($cur_percent++, $new_percent, $percent_str);
            }
            $line = fgets($file_handle);
        }
        printNewPercent($cur_percent, "100", $percent_str);
        $percent = intval($count/$total_lines * 100);
        echo "\nFinished reading/writing data!\n" .
        "There were $count useful Stream5 messages which accounted for $percent% of all of the messsages. ".
        "Note that not all stream5 messages contain useful data (i.e. bulk prunes).\n\n".
        "CSV file: $output_file\n";
    }
}

/*
 * Accepts map type and the array of set values as parameters and reutrns a csv string of the values.
 */ 
function getCSVString($map_type, $set_array) {
//stream5 states 
$s5ss = $s5ssa = $s5sa = $s5se = $s5sdc = $s5sds = $s5sm = $s5st = $s5su = $s5sc = $s5sn =
//session flags
$sfsc = $sfssrv = $sfe = $sfnmap = $sfecq = $sfesr = $sfhttp = $sfspmat = $sfm = $sfcf = $sfsf = $sfcp = $sfsp = $sfci = $sfce =
$sfcc = $sft = $sfp = $sfr = $sfdc = $sfds = $sflqf = $sfsob = $sffb = $sfcs = $sfcsd = $sfa = $sfn = "0";

$return_csv = "";
    switch ($map_type) {
        case 'state':
            foreach ($set_array as $state_set) {
                switch ($state_set) {
                    case 'STREAM5_STATE_SYN':
                        $s5ss = "1";
                        break;
                    case 'STREAM5_STATE_SYN_ACK':
                        $s5ssa = "1";
                        break;
                    case 'STREAM5_STATE_ACK':
                        $s5sa = "1";
                        break;
                    case 'STREAM5_STATE_ESTABLISHED':
                        $s5se = "1";
                        break;
                    case 'STREAM5_STATE_DROP_CLIENT':
                        $s5sdc = "1";
                        break;
                    case 'STREAM5_STATE_DROP_SERVER':
                        $s5sds = "1";
                        break;
                    case 'STREAM5_STATE_MIDSTREAM':
                        $s5sm = "1";
                        break;
                    case 'STREAM5_STATE_TIMEDOUT':
                        $s5st = "1";
                        break;
                    case 'STREAM5_STATE_UNREACH':
                        $s5su = "1";
                        break;
                    case 'STREAM5_STATE_CLOSED':
                        $s5sc = "1";
                        break;
                    case 'STREAM5_STATE_NONE':
                        $s5n = "1";
                        break;
                    default:
                        echo "Didn't recognize state '$state_string'!\n";
                        break;
                }
            }
            return "$s5sn,$s5ss,$s5ssa,$s5sa,$s5se,$s5sdc,$s5sds,$s5sm,$s5st,$s5su,$s5sc";
            break;
        case 'flags':
            foreach ($set_array as $flag_set) {
                switch ($flag_set) {
                    case 'SSNFLAG_SEEN_CLIENT':
                        $sfsc = "1";
                        break;
                    case 'SSNFLAG_SEEN_SENDER':
                        $sfsc = "1";
                        break;
                    case 'SSNFLAG_SEEN_SERVER':
                        $sfssrv = "1";
                        break;
                    case 'SSNFLAG_SEEN_RESPONDER':
                        $sfssrv = "1";
                        break;
                    case 'SSNFLAG_ESTABLISHED':
                        $sfe = "1";
                        break;
                    case 'SSNFLAG_NMAP':
                        $sfnmap = "1";
                        break;
                    case 'SSNFLAG_ECN_CLIENT_QUERY':
                        $sfecq = "1";
                        break;
                    case 'SSNFLAG_ECN_SERVER_REPLY':
                        $sfesr = "1";
                        break;
                    case 'SSNFLAG_HTTP_1_1':
                        $sfhttp = "1";
                        break;
                    case 'SSNFLAG_SEEN_PMATCH':
                        $sfspmat = "1";
                        break;
                    case 'SSNFLAG_MIDSTREAM':
                        $sfm = "1";
                        break;
                    case 'SSNFLAG_CLIENT_FIN':
                        $sfcf = "1";
                        break;
                    case 'SSNFLAG_SERVER_FIN':
                        $sfsf = "1";
                        break;
                    case 'SSNFLAG_CLIENT_PKT':
                        $sfcp = "1";
                        break;
                    case 'SSNFLAG_SERVER_PKT':
                        $sfsp = "1";
                        break;
                    case 'SSNFLAG_COUNTED_INITIALIZE':
                        $sfci = "1";
                        break;
                    case 'SSNFLAG_COUNTED_ESTABLISH':
                        $sfce = "1";
                        break;
                    case 'SSNFLAG_COUNTED_CLOSING':
                        $sfcc = "1";
                        break;  
                    case 'SSNFLAG_TIMEDOUT':
                        $sft = "1";
                        break;                            
                    case 'SSNFLAG_PRUNED':
                        $sfp = "1";
                        break;                            
                    case 'SSNFLAG_RESET':
                        $sfr = "1";
                        break;                            
                    case 'SSNFLAG_DROP_CLIENT':
                        $sfdc = "1";
                        break;                            
                    case 'SSNFLAG_DROP_SERVER':
                        $sfds = "1";
                        break;                            
                    case 'SSNFLAG_LOGGED_QUEUE_FULL':
                        $sflqf = "1";
                        break;                            
                    case 'SSNFLAG_STREAM_ORDER_BAD':
                        $sfsob = "1";
                        break;                            
                    case 'SSNFLAG_FORCE_BLOCK':
                        $sffb = "1";
                        break;                            
                    case 'SSNFLAG_CLIENT_SWAP':
                        $sfcs = "1";
                        break;                            
                    case 'SSNFLAG_CLIENT_SWAPPED':
                        $sfcsd = "1";
                        break;
                    case 'SSNFLAG_ALL':
                        $sfa = "1";
                        break; 
                    case 'SSNFLAG_NONE':
                        $sfn = "1";
                        break;                   
                    default:
                        echo "Didn't recognize state '$state_string'!\n";
                        break;
                }
            }    
            return "$sfsc,$sfssrv,$sfe,$sfnmap,$sfecq,$sfesr,$sfhttp,$sfspmat,$sfm,$sfcf,$sfsf,$sfcp,$sfsp,$sfci,$sfce,$sfcc,".
                   "$sft,$sfp,$sfr,$sfdc,$sfds,$sflqf,$sfsob,$sffb,$sfcs,$sfcsd,$sfa,$sfn";        
            break;
        default:
            echo "Did not recognize map type $map_type'!\n";
            break;
    }
}
/*
 * Accepts a flag hex string as a parameter and returns an array of 
 * strings containing all of the flags set.
 * The array returned is an associative array of strings where the key
 * and value are both the string value of the flag.
 */ 
function getFlagsSet($flag_hex_string) {
    global $flag_array;
    $flag_hex = hexdec($flag_hex_string);
    $flags_set = array();
    foreach ($flag_array as $flag_string => $flag_hex_value) {
        if($flag_hex & $flag_hex_value) 
            $flags_set[$flag_string] = $flag_string;
    }
    return $flags_set;
}

function getStatesSet($state_hex_string) {
    global $state_array;
    $state_hex = hexdec($state_hex_string);
    $states_set = array();
    foreach ($state_array as $state_string => $state_hex_value) {
        if($state_hex & $state_hex_value) 
            $states_set[$state_string] = $state_string;
    }
    return $states_set;
}

function setMapColor($map_type, $set_array, $color = "green") {
    
    global $a0, $b0, $c0, $d0, $e0, $f0, $g0, $h0, $i0, $j0,
           $a1, $b1, $c1, $d1, $e1, $f1, $g1, $h1, $i1, $j1,
           $a2, $b2, $c2, $d2, $e2, $f2, $g2, $h2, $i2, $j2,
           $a3, $b3, $c3, $d3, $e3, $f3, $g3, $h3, $i3, $j3,
           $colors;
    $a0 = $b0 = $c0 = $d0 = $e0 = $f0 = $g0 = $h0 = $i0 = $j0 = "0";
    $a1 = $b1 = $c1 = $d1 = $e1 = $f1 = $g1 = $h1 = $i1 = $j1 = "|";
    $a2 = $b2 = $c2 = $d2 = $e2 = $f2 = $g2 = $h2 = $i2 = $j2 = "+";
    $a3 = $b3 = $c3 = $d3 = $e3 = $f3 = $g3 = $h3 = $i3 = $j3 = "-";
    $vertical = $colors->getColoredString("|", $color);
    $cross = $colors->getColoredString("+", $color);
    $horitzonal = $colors->getColoredString("-", $color);
    $one = $colors->getColoredString("1", $color);
    
    switch ($map_type) {
        case 'state':  
           global $stream5_state_syn, $stream5_state_syn_ack, $stream5_state_ack,
                  $stream5_state_established, $stream5_state_drop_client, $stream5_state_drop_server,
                  $stream5_state_midstream, $stream5_state_timedout, $stream5_state_unreach,
                  $stream5_state_closed, $stream5_state_none, 
                  $state_array, $stream5_state_map_reference;
            foreach ($set_array as $state_string) {
                $map_letter0 = $stream5_state_map_reference[$state_string]['map_letter'] . "0";
                $map_letter1 = $stream5_state_map_reference[$state_string]['map_letter'] . "1";
                $map_letter2 = $stream5_state_map_reference[$state_string]['map_letter'] . "2";
                $map_letter3 = $stream5_state_map_reference[$state_string]['map_letter'] . "3";
                $map_var = $stream5_state_map_reference[$state_string]['map_var'];
                $$map_letter0 = $one;
                $$map_letter1 = $vertical;
                $$map_letter2 = $cross;
                $$map_letter3 = $horitzonal;
                $$map_var = $colors->getColoredString($state_string, $color);                    
            }
            redefineMap("state");
            break;
        case 'flag':
            global $session_flag_map_reference, $flag_array,
                   $sfsc,$sfssrv,$sfe,$sfnmap,$sfecq,$sfesr,$sfhttp,$sfspmat,$sfm,$sfcf,$sfsf,$sfcp,
                   $sfsp,$sfci,$sfce,$sfcc,$sft,$sfp,$sfr,$sfdc,$sfds,$sflqf,$sfsob,$sffb,$sfcs,$sfcsd,
                   $k0,$l0,$m0,$n0,$o0,$p0,$q0,$r0,$s0,$t0,$u0,$v0,$w0,$x0,$y0,$z0,
                   $k1,$l1,$m1,$n1,$o1,$p1,$q1,$r1,$s1,$t1,$u1,$v1,$w1,$x1,$y1,$z1,
                   $k2,$l2,$m2,$n2,$o2,$p2,$q2,$r2,$s2,$t2,$u2,$v2,$w2,$x2,$y2,$z2,
                   $k3,$l3,$m3,$n3,$o3,$p3,$q3,$r3,$s3,$t3,$u3,$v3,$w3,$x3,$y3,$z3;
            foreach ($set_array as $flag_string) {
                $map_letter0 = $session_flag_map_reference[$flag_string]['map_letter'] . "0";
                $map_letter1 = $session_flag_map_reference[$flag_string]['map_letter'] . "1";
                $map_letter2 = $session_flag_map_reference[$flag_string]['map_letter'] . "2";
                $map_letter3 = $session_flag_map_reference[$flag_string]['map_letter'] . "3";
                $map_var = $session_flag_map_reference[$flag_string]['map_var'];
                $$map_letter0 = $one;
                $$map_letter1 = $vertical;
                $$map_letter2 = $cross;
                $$map_letter3 = $horitzonal;
                $$map_var = $colors->getColoredString($flag_string, $color);
            }
            redefineMap("flag");
            break;         
        default:
            echo "Didn't recognize map type '$map_type'!\n";
            exit(1);
    }      
}

function redefineMap($type){
     /*State Map Template
                "\t    |||||||| ||$s|||\n".
                "\t01) |||||||| |||||||+-- STREAM5_STATE_SYN\n".
                "\t02) |||||||| ||||||+--- STREAM5_STATE_SYN_ACK\n".
                "\t03) |||||||| |||||+---- STREAM5_STATE_ACK\n".
                "\t04) |||||||| ||||+----- STREAM5_STATE_ESTABLISHED\n".
                "\t05) |||||||| |||+------ STREAM5_STATE_DROP_CLIENT\n".
                "\t06) |||||||| ||+------- $stream_state_drop\n". //STREAM5_STATE_DROP_SERVER
                "\t07) |||||||| |+-------- STREAM5_STATE_MIDSTREAM\n".
                "\t08) |||||||| +--------- STREAM5_STATE_TIMEDOUT\n".
                "\t    ||||||||\n" .
                "\t09) |||||||+----------- STREAM5_STATE_UNREACH\n".
                "\t    ||||||+\n".
                "\t    |||||+\n".
                "\t10) ||||+-------------- STREAM5_STATE_CLOSED\n".
                "\t11) 00000000 00000000-- STREAM5_STATE_NONE\n\n";*/
    /*Flag Map Template
                "\t    |||||||| |||||||| |||||||| ||||||||\n".
                "\t01) |||||||| |||||||| |||||||| |||||||+-- SSNFLAG_SEEN_CLIENT\n".
                "\t02) |||||||| |||||||| |||||||| ||||||+--- SSNFLAG_SEEN_SERVER\n".
                "\t03) |||||||| |||||||| |||||||| |||||+---- SSNFLAG_ESTABLISHED\n".
                "\t04) |||||||| |||||||| |||||||| ||||+----- SSNFLAG_NMAP\n".
                "\t05) |||||||| |||||||| |||||||| |||+------ SSNFLAG_ECN_CLIENT_QUERY\n".
                "\t06) |||||||| |||||||| |||||||| ||+------- SSNFLAG_ECN_SERVER_REPLY\n".
                "\t07) |||||||| |||||||| |||||||| |+-------- SSNFLAG_HTTP_1_1\n".
                "\t08) |||||||| |||||||| |||||||| +--------- SSNFLAG_SEEN_PMATCH (pattern match)\n".
                "\t    |||||||| |||||||| ||||||||\n" .
                "\t09) |||||||| |||||||| |||||||+----------- SSNFLAG_MIDSTREAM\n".
                "\t10) |||||||| |||||||| ||||||+------------ SSNFLAG_CLIENT_FIN\n".
                "\t11) |||||||| |||||||| |||||+------------- SSNFLAG_SERVER_FIN\n".
                "\t12) |||||||| |||||||| ||||+-------------- SSNFLAG_CLIENT_PKT\n".
                "\t13) |||||||| |||||||| |||+--------------- SSNFLAG_SERVER_PKT\n".
                "\t14) |||||||| |||||||| ||+---------------- SSNFLAG_COUNTED_INITIALIZE\n".
                "\t15) |||||||| |||||||| |+----------------- SSNFLAG_COUNTED_ESTABLISH\n".
                "\t16) |||||||| |||||||| +------------------ SSNFLAG_COUNTED_CLOSING\n".
                "\t    |||||||| ||||||||\n" .
                "\t17) |||||||| |||||||+-------------------- SSNFLAG_TIMEDOUT\n".
                "\t18) |||||||| ||||||+--------------------- SSNFLAG_PRUNED\n".
                "\t19) |||||||| |||||+---------------------- SSNFLAG_RESET\n".
                "\t20) |||||||| ||||+----------------------- SSNFLAG_DROP_CLIENT\n".
                "\t21) |||||||| |||+------------------------ SSNFLAG_DROP_SERVER\n".
                "\t22) |||||||| ||+------------------------- SSNFLAG_LOGGED_QUEUE_FULL\n".
                "\t23) |||||||| |+-------------------------- SSNFLAG_STREAM_ORDER_BAD\n".
                "\t24) |||||||| +--------------------------- SSNFLAG_FORCE_BLOCK\n".
                "\t    ||||||||\n" .
                "\t25) |||||||+----------------------------- SSNFLAG_CLIENT_SWAP\n".
                "\t26) ||||||+------------------------------ SSNFLAG_CLIENT_SWAPPED\n".
                "\t27) 11111111 11111111 11111111 11111111-- SSNFLAG_ALL\n".
                "\t28) 00000000 00000000 00000000 00000000-- SSNFLAG_NONE\n\n";*/
                
    global $a0, $b0, $c0, $d0, $e0, $f0, $g0, $h0, $i0, $j0,
           $a1, $b1, $c1, $d1, $e1, $f1, $g1, $h1, $i1, $j1,
           $a2, $b2, $c2, $d2, $e2, $f2, $g2, $h2, $i2, $j2,
           $a3, $b3, $c3, $d3, $e3, $f3, $g3, $h3, $i3, $j3, $z;
           
    switch ($type) {
        case 'state':
            global $stream5_state_map,$stream5_state_syn, $stream5_state_syn_ack, $stream5_state_ack,
                   $stream5_state_established, $stream5_state_drop_client, $stream5_state_drop_server,
                   $stream5_state_midstream, $stream5_state_timedout, $stream5_state_unreach,
                   $stream5_state_closed, $stream5_state_none;
            $stream5_state_map = 
              "\t##) 0000$j0$z$z$i0 $h0$g0$f0$e0$d0$c0$b0$a0\n".
                "\t    ||||$j1||$i1 $h1$g1$f1$e1$d1$c1$b1$a1\n".
                "\t01) ||||$j1||$i1 $h1$g1$f1$e1$d1$c1$b1$a2$a3$a3 $stream5_state_syn\n".
                "\t02) ||||$j1||$i1 $h1$g1$f1$e1$d1$c1$b2$b3$b3$b3 $stream5_state_syn_ack\n".
                "\t03) ||||$j1||$i1 $h1$g1$f1$e1$d1$c2$c3$c3$c3$c3 $stream5_state_ack\n".
                "\t04) ||||$j1||$i1 $h1$g1$f1$e1$d2$d3$d3$d3$d3$d3 $stream5_state_established\n".
                "\t05) ||||$j1||$i1 $h1$g1$f1$e2$e3$e3$e3$e3$e3$e3 $stream5_state_drop_client\n".
                "\t06) ||||$j1||$i1 $h1$g1$f2$f3$f3$f3$f3$f3$f3$f3 $stream5_state_drop_server\n". //STREAM5_STATE_DROP_SERVER
                "\t07) ||||$j1||$i1 $h1$g2$g3$g3$g3$g3$g3$g3$g3$g3 $stream5_state_midstream\n".
                "\t08) ||||$j1||$i1 $h2$h3$h3$h3$h3$h3$h3$h3$h3$h3 $stream5_state_timedout\n".
                "\t    ||||$j1||$i1\n" .
                "\t09) ||||$j1||$i2$i3$i3$i3$i3$i3$i3$i3$i3$i3$i3 $stream5_state_unreach\n".
                "\t    ||||$j1|+\n".
                "\t    ||||$j1+\n".
                "\t10) ||||$j2$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3 $stream5_state_closed\n".
                "\t11) 00000000 00000000-- STREAM5_STATE_NONE\n\n";
            break;
        case 'flag':
            global $session_flag_map,$session_flag_map_reference,
                   $sfsc,$sfssrv,$sfe,$sfnmap,$sfecq,$sfesr,$sfhttp,$sfspmat,$sfm,$sfcf,$sfsf,$sfcp,
                   $sfsp,$sfci,$sfce,$sfcc,$sft,$sfp,$sfr,$sfdc,$sfds,$sflqf,$sfsob,$sffb,$sfcs,$sfcsd,
                   $k0,$l0,$m0,$n0,$o0,$p0,$q0,$r0,$s0,$t0,$u0,$v0,$w0,$x0,$y0,$z0,
                   $k1,$l1,$m1,$n1,$o1,$p1,$q1,$r1,$s1,$t1,$u1,$v1,$w1,$x1,$y1,$z1,
                   $k2,$l2,$m2,$n2,$o2,$p2,$q2,$r2,$s2,$t2,$u2,$v2,$w2,$x2,$y2,$z2,
                   $k3,$l3,$m3,$n3,$o3,$p3,$q3,$r3,$s3,$t3,$u3,$v3,$w3,$x3,$y3,$z3;
            $session_flag_map =
                "\t##) 000000$z0$y0 $x0$w0$v0$u0$t0$s0$r0$q0 $p0$o0$n0$m0$l0$k0$j0$i0 $h0$g0$f0$e0$d0$c0$b0$a0\n".
                "\t    ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e1$d1$c1$b1$a1\n".
                "\t11) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e1$d1$c1$b1$a2$a3$a3 $sfsc\n".
                "\t12) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e1$d1$c1$b2$b3$b3$b3 $sfssrv\n".
                "\t13) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e1$d1$c2$c3$c3$c3$c3 $sfe\n".
                "\t14) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e1$d2$d3$d3$d3$d3$d3 $sfnmap\n".
                "\t15) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f1$e2$e3$e3$e3$e3$e3$e3 $sfecq\n".
                "\t16) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g1$f2$f3$f3$f3$f3$f3$f3$f3 $sfesr\n". 
                "\t17) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h1$g2$g3$g3$g3$g3$g3$g3$g3$g3 $sfhttp\n".
                "\t18) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1 $h2$h3$h3$h3$h3$h3$h3$h3$h3$h3 $sfspmat\n".
                "\t    ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i1\n" .
                "\t19) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j1$i2$i3$i3$i3$i3$i3$i3$i3$i3$i3$i3 $sfm\n".
                "\t11) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k1$j2$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3$j3 $sfcf\n".
                "\t11) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l1$k2$k3$k3$k3$k3$k3$k3$k3$k3$k3$k3$k3$k3 $sfsf\n".
                "\t12) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m1$l2$l3$l3$l3$l3$l3$l3$l3$l3$l3$l3$l3$l3$l3 $sfcp\n".
                "\t13) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n1$m2$m3$m3$m3$m3$m3$m3$m3$m3$m3$m3$m3$m3$m3$m3 $sfsp\n".
                "\t14) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o1$n2$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3$n3 $sfci\n".
                "\t15) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p1$o2$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3$o3 $sfce\n".
                "\t16) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1 $p2$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3$p3 $sfcc\n".
                "\t    ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q1\n" .
                "\t17) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r1$q2$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3$q3 $sft\n".
                "\t18) ||||||$z1$y1 $x1$w1$v1$u1$t1$s1$r2$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3$r3 $sfp\n".
                "\t19) ||||||$z1$y1 $x1$w1$v1$u1$t1$s2$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3$s3 $sfr\n".
                "\t20) ||||||$z1$y1 $x1$w1$v1$u1$t2$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3$t3 $sfdc\n".
                "\t21) ||||||$z1$y1 $x1$w1$v1$u2$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3$u3 $sfds\n".
                "\t22) ||||||$z1$y1 $x1$w1$v2$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3$v3 $sflqf\n".
                "\t23) ||||||$z1$y1 $x1$w2$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3$w3 $sfsob\n".
                "\t22) ||||||$z1$y1 $x2$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3$x3 $sffb\n".
                "\t    ||||||$z1$y1\n".
                "\t23) ||||||$z1$y2$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3$y3 $sfcs\n".
                "\t22) ||||||$z2$y3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3$z3 $sfcsd\n".
                "\t27) 11111111 11111111 11111111 11111111-- SSNFLAG_ALL\n".
                "\t28) 00000000 00000000 00000000 00000000-- SSNFLAG_NONE\n\n";  
                break;
        default:
            echo "Didn't recognize map type '$type'!\n";
            exit(1);
    }        
}
/********************End Functions********************************/
?>
