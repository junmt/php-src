--TEST--
rfc1867: unused multipart part headers are not kept in memory (CVE-2026-109618)
--SKIPIF--
<?php
if (!getenv('TEST_PHP_CGI_EXECUTABLE')) die('skip TEST_PHP_CGI_EXECUTABLE not set');
if (!function_exists('proc_open')) die('skip proc_open() not available');
?>
--FILE--
<?php
$boundary = 'xxBOUNDARYxx';
$body = "--$boundary\r\n"
	. "Content-Disposition: form-data; name=\"a\"\r\n"
	. "Content-Disposition: form-data; name=\"ignored_duplicate\"\r\n"
	. str_repeat("X:\r\n", 100000)
	. "\r\n"
	. "value\r\n"
	. "--$boundary--\r\n";

$script = tempnam(sys_get_temp_dir(), 'rfc1867');
file_put_contents($script, '<?php var_dump($_POST);');

$env = array(
	'REDIRECT_STATUS' => '1',
	'REQUEST_METHOD' => 'POST',
	'SCRIPT_FILENAME' => $script,
	'CONTENT_TYPE' => "multipart/form-data; boundary=$boundary",
	'CONTENT_LENGTH' => strlen($body),
);
$cmd = escapeshellarg(getenv('TEST_PHP_CGI_EXECUTABLE'))
	. ' -n -d memory_limit=4M -d post_max_size=8M -d display_errors=1 -d html_errors=0';
$proc = proc_open($cmd, array(array('pipe', 'r'), array('pipe', 'w')), $pipes, null, $env);
fwrite($pipes[0], $body);
fclose($pipes[0]);
$out = stream_get_contents($pipes[1]);
fclose($pipes[1]);
proc_close($proc);
unlink($script);

echo substr($out, strpos($out, "\r\n\r\n") + 4);
?>
--EXPECT--
array(1) {
  ["a"]=>
  string(5) "value"
}
