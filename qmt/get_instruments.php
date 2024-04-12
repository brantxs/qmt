<?php
date_default_timezone_set('PRC');

$dbhost='localhost';
$dbuser='root';
$dbpwd = '***********';

$myfile = fopen("/server/html/log.txt", "wa");

$conn=mysqli_connect($dbhost,$dbuser,$dbpwd);
if (mysqli_connect_errno($conn)) 
{
   fwrite($myfile, "数据库连接失败");
   exit();
}

$db=mysqli_select_db($conn,"currency_okx");

$start = $_GET["start"];
$end = $_GET["end"];
$flag = $_GET["flag"];


$sql = "SELECT instId,baseCcy,quoteCcy,lastTime,lastTime_1m FROM `instruments` WHERE id >= ".$start." and id <= ".$end." and flag = ".$flag;
$result=mysqli_query($conn,$sql);
$rownum=mysqli_num_rows($result);
$ret="[";
while ($rows=mysqli_fetch_array($result))
{
    $instId = $rows[0];
    $baseCcy = $rows[1];
    $quoteCcy = $rows[2];
    $lastTime = $rows[3];
    $lastTime1m = $rows[4];

    $ret = $ret.'{"instId":"'.$instId.'","baseCcy":"'.$baseCcy.'","quoteCcy":"'.$quoteCcy.'","lastTime":'.$lastTime.',"lastTime1m":'.$lastTime1m.'},';
}
if ($rownum > 0) {
   $ret = substr($ret,0,-1);
}
$ret = $ret."]";

//fwrite($myfile, $ret);

fclose($myfile);

echo $ret;

//addslashes(gzcompress(json_encode($detail_array, 9));

?>
