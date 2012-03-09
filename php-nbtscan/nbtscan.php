<?php
/**
* Open Snapt http://snapt.github.com
* 
* nbtscan PHP class 
* 
* Allows you to send a netbios query to a windows (or smb) server 
* to return the name of the user on that system.
* 
* This can be expanded to get more information quite easily. It 
* was developed for our cache class to scan local ips, without 
* requiring additional binaries (e.g. nbtscan)
* 
* 
*/

class nbtscan {
    private $ip = '';
    
    /**
    * @desc Constructor
    */
    public function __construct() {
        
        // We have caching functions in here, which use Zend_Cache
        // It's wise to cache this data, as the system may be offline when you 
        // check again, and it's much quicker to cache misses because of UDP
        // being impossible to check with aside from waiting per request.
        
    }
    
    
    /**
    * Execute a scan against an ip, return false in the event of a miss
    * 
    * @param mixed $ip
    * @return mixed
    */
    public function scan($ip) 
    {                
        $this->ip = $ip;
            
        // If we get a response, return it, else return a false
        if ($response = $this->send_request()) return $this->decode_response($response);         
        else return false;
                   
    }
    
    
    
    
    /**
    * Send the UDP data to our potential windows host
    * Most of the understanding for this is from nbtscan - http://www.unixwiz.net/tools/nbtscan.html
    * 
    * @return mixed
    */
    private function send_request() 
    {
        
        // Initial udp connection
        $socket = fsockopen('udp://' . $this->ip, 137, $errno, $errstr, 5);
        if ($errno > 0) return false;
        
        // Set the timeout for the entire stream
        stream_set_timeout($socket, 0, (250000*2)); // 250,000 microseconds should be correct, but double it to be safe. (Half a second)
        
        // Fixed variables
        $flags = '0';
        $name = "*";
        $pad = "\x00";
        $suffix = '0';
        $qtype = "33";
        
        // Setup the data packet
        $data = pack('n*', rand(1, 65000), $flags, 1, 0, 0, 0);
        $data .= $this->encode_name($name, $pad, $suffix);
        $data .= pack('n*', $qtype, 0x0001);   
                
        // Send the request
        fwrite($socket, $data);
        
        // Read 1 byte, seed the meta data
        $response = $char = fgetc($socket);
        $meta = stream_get_meta_data($socket);

        // Loop till the end
        while ($meta['unread_bytes'] != 0) {
            $char = fgetc($socket);
            $response .= $char;
            $meta = stream_get_meta_data($socket);
        }
        
        return $response;
    }
    
    
    
    /**
    * Decode a valid response; we are only currently interested in [0] as thats the name
    * 
    * @param mixed $resp
    * @return string
    */
    private function decode_response($resp) 
    {
        
            $returned = array();
        
            $num_names = implode('', unpack("C", substr($resp, 56)));
            $name_data = substr($resp, 57);

            for ($i = 0; $i < $num_names; $i++) {
                $rr_data = substr($name_data, 18*$i, 18);                
                $returned[$i] = implode('', unpack("a15Cn", $rr_data));                
            }        
                       
            return $new_string = trim(ereg_replace('[^A-Za-z0-9_\-]', "", $returned[0]));
    }
        
         
    
    
    /**
    * Encode the name, currently our usage is just for * but this will support future queries
    * 
    * @param string $name
    * @param mixed $pad
    * @param mixed $suffix
    * @returm mixed
    */
    private function encode_name($name, $pad, $suffix) 
    {
    
        $name = str_pad($name, 16, $pad);
        $name[16] = chr($suffix  & 0xFF);
        
        $encoded_name = '';
        
        foreach(unpack("C16", $name) as $c) {
           $encoded_name .= chr(ord('A') + (($c & 0xF0) >> 4));
           $encoded_name .= chr(ord('A') + ($c & 0xF));
        }
        
        return "\x20" . $encoded_name . "\x00";
    }

}
?>