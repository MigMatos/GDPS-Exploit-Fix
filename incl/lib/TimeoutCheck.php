<?php


/*
        Codes
    -700 Levels
    -701 Accounts
    -705 Accounts Tools
    -702 Comments
    -703 Timeouted
	-706 TimeOut ReuploadLevel
*/

//Class
class TimeoutCheck {



    public static function NoTimeoutOrDie($ip, $code_timeout)
    {
        include dirname(__FILE__)."/connection.php";


        //  Timeouts Config
        
        $timeout_levels = 60;
        $timeout_accounts = 200;
        $timeout_comments = 60;
        $max_errors_timeout = 50;
        $global_timeout = 500;
        #$max_request_per_day = 30;

        if ($code_timeout == -700) {
            $timeout = $timeout_levels;
        }
        elseif ($code_timeout == -701 || $code_timeout == -705) {
            $timeout = $timeout_accounts;
        }
        elseif ($code_timeout == -702) {
            $timeout = $timeout_comments;
        }
        elseif ($code_timeout == -703) {
            $timeout = 86400;
        }
		elseif ($code_timeout == -706) {
            $timeout = $timeout_levels;
        }
        else{
            $timeout = $global_timeout;
        }
        
        $next_timestamp = time() - $timeout;
		$query = $db->prepare("SELECT count(*) FROM actions WHERE type = :codetimeout AND timestamp >= :timestamp");
		$query->execute([':codetimeout' => $code_timeout,':timestamp' => $next_timestamp]);
        $data = $query->fetchColumn();
        //echo "<br>Sucess! -> data: $data with $code_timeout with next_timestamp: $next_timestamp";

        if($code_timeout == -703 && $data >= $max_errors_timeout){
            exit("-1");
        }
        elseif($code_timeout == -705 && $data >= 1){
            self::InsertTimeout($ip, -703);
            exit("<br><h2>Please wait $timeout seconds before registering another account</h2>");
        }
		elseif($code_timeout == -706 && $data >= 1){
            self::InsertTimeout($ip, -703);
            exit("<br><h2>Please wait $timeout seconds before re-upload another level</h2>");
        }
        elseif($code_timeout != -703 && $data >= 1){
            self::InsertTimeout($ip, -703);
            exit("-1");
		}
    }

    public static function InsertTimeout($ip, $code_timeout){
        include dirname(__FILE__)."/connection.php";
        $message = "Timeout Checker AntiRaid";
        if ($code_timeout == -700) {$message = "Timeout Level";}
        elseif ($code_timeout == -701 || $code_timeout == -705) {$message = "Timeout Accounts";}
        elseif ($code_timeout == -702) {$message = "Timeout Comments";}
        elseif ($code_timeout == -703) {$message = "Timeout Error";} 
		elseif ($code_timeout == -706) {$message = "Timeout ReuploadLevel";} 
        else {$message = "Timeout Unknown";}
        $query = $db->prepare("INSERT INTO actions (type, value, value2, timestamp) VALUES (:codetimeout, :ip, :history, :timestamp)");
		$query->execute([':codetimeout' => $code_timeout, ':ip' => $ip,':history' => $message, ':timestamp' => time()-5]);
    }

    public static function CheckTimeout($code_timeout){
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
			$ip = $_SERVER['HTTP_CLIENT_IP'];
		} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} else {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
        self::CheckisBlocked($ip);
        self::NoTimeoutOrDie($ip, -703);
        self::NoTimeoutOrDie($ip, $code_timeout);
        self::InsertTimeout($ip, $code_timeout);
    }

    public static function CheckisBlocked($ip){
        include dirname(__FILE__)."/../../config/antiRaidConfig.php";
        if (!self::CheckIPisValid($ip)){exit("-1");}
        for ($i=0; $i < count($blocked_ips); $i++) 
        { if($ip == $blocked_ips[$i])
            {exit("-1");}
        }
    }

    public static function CheckIPisValid($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {return true;}
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {return true;}
        return false;
    }

}

?>