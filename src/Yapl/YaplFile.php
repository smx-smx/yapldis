<?php
/**
  * @author Stefano Moioli
  * @copyright 2021 Stefano Moioli
  * @license https://opensource.org/licenses/Zlib
  */

namespace Smx\Yapl;

use Exception;
use InvalidArgumentException;
use LogicException;
use Smx\Core\InvalidDataException;
use Smx\Utils\Struct;
use stdClass;

abstract class YaplOp {
	const LDCI = 0;
	const LDCS = 1;
	const LDL = 2;
	const LDG = 3;
	const LDA = 4;
	const ADL = 5;
	const ADG = 6;
	const ADA = 7;
	const AAE = 8;
	const AAEW = 9;
	const AME = 10;
	const AMEW = 11;
	const LDI = 12;
	const LDN = 13;
	const LDK = 14;
	const STO = 15;
	const STK = 16;
	const POP = 17;
	const J = 18;
	const BZ = 19;
	const BNE = 20;
	const CALL = 21;
	const RET = 22;
	const MBP = 23;
	const HALT = 24;
	const ADD = 25;
	const SUB = 26;
	const MUL = 27;
	const DIV = 28;
	const MOD = 29;
	const INCL = 30;
	const BAND = 31;
	const BOR = 32;
	const BNOT = 33;
	const LAND = 34;
	const LOR = 35;
	const LNOT = 36;
	const CEQ = 37;
	const CNE = 38;
	const CGT = 39;
	const CGE = 40;
	const CLT = 41;
	const CLE = 42;
	const STRPRI = 43;
	const STRGET = 44;
	const TPLSRC = 45;
	const TPLREAD = 46;
	const CALLD = 47;
}

class YaplFile {
	private $fh;
	private int $fileSize;
	
	private static ?Struct $hdrT = null;
	private $hdr;
	
	private $stringPool = array();
	private $functions = array();

	private bool $loaded = false;
	private int $code_offset;

	private static function init(){
		if(self::$hdrT === null){
			self::$hdrT = new Struct(array(
				'magic' => 'a4',
				'type' => 'N',
				'num_strings' => 'N',
				'num_functions' => 'N',
			));
		}
	}

	private static function unpack(string $def, string $data, int $offset = 0){
		return array_values(\unpack($def, $data, $offset));
	}

	public function __construct(string $filePath){
		self::init();
		
		$this->fh = fopen($filePath, 'rb');
		$this->fileSize = filesize($filePath);
		$this->hdr = (self::$hdrT)->fromStream($this->fh);

		if($this->hdr->magic !== 'Yapl'){
			throw new InvalidDataException("Invalid header");
		}
	}

	private function readCstring(){
		$buf = '';
		while(!feof($this->fh)){
			$ch = fgetc($this->fh);
			if($ch == "\x00") break;
			$buf .= $ch;
		}
		return $buf;
	}

	private function readFunctionEntry(){
		$func = new stdClass;
		$func->name = $this->readCstring();
		list($func->code_offset) = self::unpack('N', fread($this->fh, 4));
		return $func;
	}

	public function load(){
		fseek($this->fh, 16);
		for($i=0; $i<$this->hdr->num_strings; $i++){
			$this->stringPool[$i] = $this->readCstring();
		}

		for($i=0; $i<$this->hdr->num_functions; $i++){
			$this->functions[$i] = $this->readFunctionEntry();
		}

		$this->code_offset = ftell($this->fh);
		$this->loaded = true;
	}

	private static function extractOpcode(int $insn){
		return $insn & 0x3F;
	}

	private static function extractOperandSize(int $insn){
		$fpVal = ($insn >> 6) & 3;
		switch($fpVal){
			case 0: return 0;
			case 1: return 1;
			case 2: return 2;
			case 3: return 4;
			default: return 4;
		}
	}

	private function dasmBuffer(string $buf, int $pc, $fhOut){
		$bufSz = strlen($buf);
		for($i=0; $i<$bufSz;){
			$pc_offset = $i;
			$cur_pc = $pc + $pc_offset;

			list($insn) = self::unpack('C', $buf[$i++]);
			
			$op = self::extractOpcode($insn);
			$opndSize = self::extractOperandSize($insn);

			$arg = 0;
			if($opndSize > 0){
				switch($opndSize){
					case 1:
						list($arg) = self::unpack('C', $buf[$i]);
						break;
					case 2:
						list($arg) = self::unpack('n', substr($buf, $i, 2));
						break;
					case 4:
						list($arg) = self::unpack('N', substr($buf, $i, 4));
						break;
				}
				$i += $opndSize;
			}

			if($op > 48){
				$opHex = dechex($op);
				throw new InvalidDataException("Invalid op 0x{$opHex} ({$op})");
			}

			fwrite($fhOut, "{$cur_pc}: ");
			switch($op){
				case YaplOp::LDCI: // LDCI(imm): local data copy integer
					fwrite($fhOut, "LDCI #{$arg}");
					break;
				case YaplOp::LDCS: // LDCS(str_idx): local data copy string
					fwrite($fhOut, "LDCS [{$arg}] // \"{$this->stringPool[$arg]}\"");
					break;
				case YaplOp::LDI: // LDI(idx): local data init (at stack top)
					fwrite($fhOut, "LDI");
					break;
				// LDN(st:var): load data new
				// var can be a var index or a string variable (which is then resolved to an index)
				case YaplOp::LDN:
					fwrite($fhOut, "LDN");
					break;
				// LDL(op:idx): load data local
				case YaplOp::LDL:
					fwrite($fhOut, "LDL [{$arg}]");
					break;
				// LDG(op:idx): load data global (variable from name)
				case YaplOp::LDG:
					fwrite($fhOut, "LDG [{$arg}] // \"{$this->stringPool[$arg]}\"");
					break;
				// LDA(op:idx): load data address
				case YaplOp::LDA:
					fwrite($fhOut, "LDA [{$arg}]");
					break;
				// STO(st:location, st:value): pop and store in frame
				case YaplOp::STO:
					fwrite($fhOut, "STO");
					break;
				// STK(st:location, st:value): store in frame without pop
				case YaplOp::STK:
					fwrite($fhOut, "STK");
					break;
				// CNE(st:a, st:b): compare non equals
				case YaplOp::CNE:
					fwrite($fhOut, "CNE");
					break;
				// CLT(st:a, st:b): compare less than
				case YaplOp::CLT:
					fwrite($fhOut, "CLT");
					break;
				// CLE(st:a, st:b): compare less than or equal
				case YaplOp::CLE:
					fwrite($fhOut, "CLE");
					break;
				// CGE(st:a, st:b): compare greater than or equal
				case YaplOp::CGE:
					fwrite($fhOut, "CGE");
					break;
				// CGT(st:a, st:b): compare greater than
				case YaplOp::CGT:
					fwrite($fhOut, "CGT");
					break;
				// CEQ(st:a, st:b): compare equals
				case YaplOp::CEQ:
					fwrite($fhOut, "CEQ");
					break;
				// ADA(op:idx): array data address
				case YaplOp::ADA:
					fwrite($fhOut, "ADA [{$arg}]");
					break;
				// ADL(op:idx): array data load
				case YaplOp::ADL: 
					fwrite($fhOut, "ADL [{$arg}]");
					break;
				// ADG(op:idx): array data global (variable from name)
				case YaplOp::ADG:
					fwrite($fhOut, "ADG [{$arg}] // \"{$this->stringPool[$arg]}\"");
					break;
				// AME(st:arr, st:idx): find Array Member Element
				case YaplOp::AME:
					fwrite($fhOut, "AME");
					break;
				// AMEW(st:arr, st:idx): find Array Member Element, create if not found
				case YaplOp::AMEW:
					fwrite($fhOut, "AMEW");
					break;
				// AAE(st:arr, st:el): Array Append Element
				case YaplOp::AAE:
					fwrite($fhOut, "AAE");
					break;
				// AAEW(st:arr, st:el): Array Append Element, create if not found
				case YaplOp::AAEW:
					fwrite($fhOut, "AAEW");
					break;
				// LDK(st:key): Load Data Key, push array key or null if invalid
				case YaplOp::LDK:
					fwrite($fhOut, "LDK");
					break;
				// BZ(op:addr): Branch to addr if Zero
				case YaplOp::BZ:
					fwrite($fhOut, "BZ #{$arg}");
					break;
				// J(op:addr): unconditional Jump to addr
				case YaplOp::J:
					fwrite($fhOut, "J #{$arg}");
					break;
				// BNE(op:addr): Branch on Not Equal to addr
				case YaplOp::BNE:
					fwrite($fhOut, "BNE #{$arg}");
					break;
				// CALL(op:str_idx): Call module function indicated by the indexed string
				case YaplOp::CALL:
					fwrite($fhOut, "CALL {$this->stringPool[$arg]}");
					break;
				// CALLD(st:str_idx): Call module function (function name from stack)
				case YaplOp::CALLD:
					fwrite($fhOut, "CALLD");
					break;
				// RET(): pop stack frame and return to caller
				case YaplOp::RET:
					fwrite($fhOut, "RET");
					break;
				// HALT(): stop VM
				case YaplOp::HALT:
					fwrite($fhOut, "HALT");
					break;
				// MOD(a: st, b: st): perform a%b and push result
				case YaplOp::MOD:
					fwrite($fhOut, "MOD");
					break;
				// ADD(a: st, b: st): perform a+b and push result
				case YaplOp::ADD:
					fwrite($fhOut, "ADD");
					break;
				// SUB(a: st, b: st): perform a-b and push result
				case YaplOp::SUB:
					fwrite($fhOut, "SUB");
					break;
				// MUL(a: st, b: st): perform a*b and push result
				case YaplOp::MUL:
					fwrite($fhOut, "MUL");
					break;
				// DIV(a: st, b: st): perform a/b and push result
				case YaplOp::DIV:
					fwrite($fhOut, "DIV");
					break;
				// MBP(): Make (push) new base pointer
				case YaplOp::MBP:
					fwrite($fhOut, "MBP");
					break;
				// INCL(var_idx): Increment Local, locals[idx]++
				case YaplOp::INCL:
					fwrite($fhOut, "INCL [{$arg}]");
					break;
				// POP(): pop variable from stack
				case YaplOp::POP:
					fwrite($fhOut, "POP");
					break;
				// LAND(st:a, st:b): perform a&&b and push result
				case YaplOp::LAND:
					fwrite($fhOut, "LAND");
					break;
				// LOR(st:a, st:b): perform a||b and push result
				case YaplOp::LOR:
					fwrite($fhOut, "LOR");
					break;
				// LNOT(st:a): perform !a and push result
				case YaplOp::LNOT:
					fwrite($fhOut, "LNOT");
					break;
				// BAND(st:a, st:b): perform a&b and push result
				case YaplOp::BAND:
					fwrite($fhOut, "BAND");
					break;
				// BAND(st:a, st:b): perform a|b and push result
				case YaplOp::BOR:
					fwrite($fhOut, "BOR");
					break;
				// BNOT(st:a): perform ~a and push result
				case YaplOp::BNOT:
					fwrite($fhOut, "BNOT");
					break;
				// STR_GET(): builtin call to 'str:get'
				case YaplOp::STRGET:
					fwrite($fhOut, "STR_GET // CALL str:get");
					break;
				// STR_PRI(): builtin call to 'str:print'
				case YaplOp::STRPRI:
					fwrite($fhOut, "STR_PRI // CALL str:print");
					break;
				// TPL_SRC(): builtin call to 'tpl:source'
				case YaplOp::TPLSRC:
					fwrite($fhOut, "TPL_SRC // CALL tpl:source");
					break;
				// TPL_READ(): builtin call to 'tpl:read'
				case YaplOp::TPLREAD:
					fwrite($fhOut, "TPL_READ // CALL tpl:read");
					break;
				default:
					$opHex = dechex($op);
					throw new Exception("Unimplemented op 0x{$opHex} ({$op})");
			}

			fwrite($fhOut, "\n");
		}
	}

	public function disassembleAll(){
		for($i=0; $i<$this->hdr->num_functions; $i++){
			$fn = $this->functions[$i]->name;
			fwrite(STDOUT, "== disassembly for '{$fn}' ==\n");
			$this->disassemble($fn);
		}
	}

	public function disassemble(string $name, $fh = STDOUT){
		if(!$this->loaded){
			throw new LogicException("Call load first");
		}


		$code_start = -1;
		$code_end = -1;

		for($i=0; $i<$this->hdr->num_functions; $i++){
			$fn = $this->functions[$i];
			if($fn->name === $name){
				$code_start = $fn->code_offset;
				if($i + 1 < $this->hdr->num_functions){
					$code_end = $this->functions[$i+1]->code_offset;
				} else {
					$code_end = $this->fileSize;
				}
				break;
			}
		}

		if($code_start === -1){
			throw new InvalidArgumentException("Function {$name} not found");
		}

		$code_length = $code_end - $code_start;
		
		$code_va = $code_start;
		$code_pa = $code_start + $this->code_offset;

		fseek($this->fh, $code_pa);

		$code_buf = fread($this->fh, $code_length);
		$this->dasmBuffer($code_buf, $code_va, $fh);
		
	}

	public function __destruct(){
		if(is_resource($this->fh)){
			fclose($this->fh);
		}
	}
}