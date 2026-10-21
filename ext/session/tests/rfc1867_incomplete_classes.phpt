--TEST--
session rfc1867: upload progress keeps objects as incomplete classes (CVE-2026-109619)
--INI--
file_uploads=1
error_reporting=E_ALL
upload_max_filesize=1024
session.save_handler=files
session.save_path={PWD}
session.name=PHPSESSID
session.cache_limiter=
session.serialize_handler=php
session.use_strict_mode=0
session.use_cookies=1
session.use_only_cookies=0
session.upload_progress.enabled=1
session.upload_progress.cleanup=0
session.upload_progress.prefix=upload_progress_
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq=1%
session.upload_progress.min_freq=0.000000001
unserialize_callback_func=rfc1867_incomplete_classes_cb
--SKIPIF--
<?php
include('skipif.inc');
/* The session must exist before the upload is processed, i.e. before the
 * script runs */
file_put_contents(__DIR__ . '/sess_rfc1867-incomplete-classes',
	'obj|O:7:"Wakeup1":1:{s:1:"a";i:1;}ser|C:5:"Ser_1":3:{abc}');
?>
--COOKIE--
PHPSESSID=rfc1867-incomplete-classes
--POST_RAW--
Content-Type: multipart/form-data; boundary=---------------------------20896060251896012921717172737
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

rfc1867_incomplete_classes.php
-----------------------------20896060251896012921717172737
Content-Disposition: form-data; name="file1"; filename="file1.txt"

1
-----------------------------20896060251896012921717172737--
--FILE--
<?php
/* $_SESSION populated by the upload progress handler must not leak */
var_dump(isset($_SESSION));

$data = file_get_contents(__DIR__ . '/sess_rfc1867-incomplete-classes');
var_dump(strpos($data, 'obj|O:7:"Wakeup1":1:{s:1:"a";i:1;}') !== false);
var_dump(strpos($data, 'ser|C:5:"Ser_1":3:{abc}') !== false);
var_dump(strpos($data, 'upload_progress_rfc1867_incomplete_classes.php|') !== false);

session_start();
var_dump(get_class($_SESSION['obj']), get_class($_SESSION['ser']));
var_dump($_SESSION['upload_progress_' . basename(__FILE__)]['done']);
session_destroy();
?>
--CLEAN--
<?php
@unlink(__DIR__ . '/sess_rfc1867-incomplete-classes');
?>
--EXPECTF--
bool(false)
bool(true)
bool(true)
bool(true)

Warning: session_start(): defined (rfc1867_incomplete_classes_cb) but not found in %s on line %d

Warning: session_start(): defined (rfc1867_incomplete_classes_cb) but not found in %s on line %d

Warning: Class __PHP_Incomplete_Class has no unserializer in %s on line %d
string(22) "__PHP_Incomplete_Class"
string(22) "__PHP_Incomplete_Class"
bool(true)
