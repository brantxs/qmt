<?php
date_default_timezone_set('PRC');

$dbhost='localhost';
$dbuser='root';
$dbpwd = '***********';

$myfile = fopen("/server/html/log1m.txt", "wa");

$conn=mysqli_connect($dbhost,$dbuser,$dbpwd);
if (mysqli_connect_errno($conn))
{
   fwrite($myfile, "数据库连接失败");
   exit();
}

$db=mysqli_select_db($conn,"currency_binance");

$str=file_get_contents('php://input');

$json_arr = json_decode($str,true);

$k1_arr=$json_arr['k1'];
$k2_arr=$json_arr['k2'];
$lastTime = $json_arr['endTime'];
$symbol = $json_arr['symbol'];
$base_asset = $json_arr['base_asset'];
$quote_asset = $json_arr['quote_asset'];

$k_arr = array_merge($k1_arr,$k2_arr);

// 更新lastTime
if (empty($k_arr)) {
    $sql = "update `exchangeInfo` set lastTime_1m=".$lastTime." where symbol='".$symbol."'";
    mysqli_query($conn,$sql);

    fclose($myfile);
    mysqli_close($conn);
    exit();
}

$marr = addslashes(gzcompress(json_encode($k_arr, 9)));

$date = date("Y-m-d", $lastTime / 1000);
$year = substr($date,0,4);

$value = "(NULL,'".$symbol."','".$base_asset."','".$quote_asset."','".$date."','".$marr."')";
$sql = "INSERT into `minute_kline_".$year."` values".$value;
mysqli_query($conn,$sql);

//$stmt = mysqli_prepare($conn,$sql);
//$stmt->bind_param("b", $marr);

//$stmt->execute();
//mysqli_stmt_close($stmt);
 
//$values = substr($values,0,-1);

//fwrite($myfile, $values);

$sql = "update `exchangeInfo` set lastTime_1m=".$lastTime." where symbol='".$symbol."'";
mysqli_query($conn,$sql);

fclose($myfile);
mysqli_close($conn);

?>
