<?php
/**
  * @author Stefano Moioli
  * @copyright 2021 Stefano Moioli
  * @license https://opensource.org/licenses/Zlib
  */
require_once __DIR__ . '/vendor/autoload.php';

use Smx\Yapl\YaplFile;

$f = new YaplFile($argv[1]);
$f->load();

$fn = $argc > 2 ? $argv[2] : null;

if($fn === null){
	$f->disassembleAll();
} else {
	fwrite(STDOUT, "== disassembly for '{$fn}' ==\n");
	$f->disassemble($fn);
}