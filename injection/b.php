<html>
<head>
    <title>命令注入测试</title>
</head>
<body>
<p>输入IP</p>
<form method="GET" action="<?php echo $_SERVER['PHP_SELF'];?>">
    IP:<input name="host" type="text" required><br>
    <input type="submit" value="提交">
    <p id="demo">我是结果</p>
</form>
</body>
</html>

<?php
header("Content-type: text/html;charset=utf-8");
if(isset($_GET['host'])){
    $ud=$_GET['host'];
    $j=check($ud);
    echo "payload：$j";
    echo "<br>";
    $zx=system("ping ".$j);
    echo $zx;
    echo "<script>document.getElementById('demo').innerText=$zx</script>";
}
function check($v){
    $black_list=array(';'=>'','&'=>'','||'=>'','|'=>'',')'=>'','('=>'');
    $th=str_replace(array_keys($black_list),$black_list,$v); /*读取黑名单数组里面的key，替换为黑名单里面的值也就是空*/
    return $th;
}
?>