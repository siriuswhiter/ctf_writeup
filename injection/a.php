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
    $zx=system("ping ".$ud);
    echo $zx;
    echo "<script>document.getElementById('demo').innerText=$zx</script>";
}
?>