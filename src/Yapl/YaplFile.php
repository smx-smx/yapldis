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
				// LDN(var): load data new
				// var can be a var index or a string variable (which is then resolved to an index)
				case YaplOp::LDN:
					fwrite($fhOut, "LDN");
					break;
				case YaplOp::LDL: // LDL(idx): load local variable from frame
					fwrite($fhOut, "LDL [{$arg}]");
					break;
				case YaplOp::LDG: // 
					fwrite($fhOut, "LDG [{$arg}] // \"{$this->stringPool[$arg]}\"");
					break;
				case YaplOp::LDA: // local data alloc
					fwrite($fhOut, "LDA [{$arg}]");
					break;
				case YaplOp::STO: // STO(location, value): pop and store in frame
					fwrite($fhOut, "STO");
					break;
				case YaplOp::STK: // STK(location, value): store in frame without pop
					fwrite($fhOut, "STK");
					break;
				case YaplOp::CNE: // CNE: compare non equals
					fwrite($fhOut, "CNE");
					break;
				case YaplOp::CLT: // CLT: compare less than
					fwrite($fhOut, "CLT");
					break;
				case YaplOp::CGT: // CGT: compare greater than
					fwrite($fhOut, "CGT");
					break;
				case YaplOp::CEQ: // CEQ: compare equals
					fwrite($fhOut, "CEQ");
					break;
				case YaplOp::ADA: 
					fwrite($fhOut, "ADA [{$arg}]");
					break;
				case YaplOp::ADL:
					fwrite($fhOut, "ADL [{$arg}]");
					break;
				case YaplOp::ADG: // ?
					fwrite($fhOut, "ADG [{$arg}] // \"{$this->stringPool[$arg]}\"");
					break;
				case YaplOp::AME: // AME: Array Member Element
					fwrite($fhOut, "AME");
					break;
				case YaplOp::AMEW: // AMEW: Array Member Element, create if not found
					fwrite($fhOut, "AMEW");
					break;
				case YaplOp::AAE: // AAE: Array Append Element
					fwrite($fhOut, "AAE");
					break;
				case YaplOp::AAEW: // AAEW: Array Append Element, create if not found
					fwrite($fhOut, "AAEW");
					break;
				case YaplOp::LDK: // LDK(): load key
					fwrite($fhOut, "LDK");
					break;
				case YaplOp::BZ:
					fwrite($fhOut, "BZ #{$arg}");
					break;
				case YaplOp::J:
					fwrite($fhOut, "J #{$arg}");
					break;
				case YaplOp::BNE:
					fwrite($fhOut, "BNE #{$arg}");
					break;
				case YaplOp::CALL:
					fwrite($fhOut, "CALL {$this->stringPool[$arg]}");
					break;
				case YaplOp::CALLD: // CALLD: indirect call (pop location from stack)
					fwrite($fhOut, "CALLD");
					break;
				case YaplOp::RET:
					fwrite($fhOut, "RET");
					break;
				case YaplOp::HALT: // HALT(): stop VM
					fwrite($fhOut, "HALT");
					break;
				case YaplOp::MOD:
					fwrite($fhOut, "MOD");
					break;
				case YaplOp::ADD:
					fwrite($fhOut, "ADD");
					break;
				case YaplOp::SUB:
					fwrite($fhOut, "SUB");
					break;
				case YaplOp::MUL:
					fwrite($fhOut, "MUL");
					break;
				case YaplOp::DIV:
					fwrite($fhOut, "DIV");
					break;
				case YaplOp::MBP: // MBP(): move (push) base pointer
					fwrite($fhOut, "MBP");
					break;
				case YaplOp::INCL: // Increment Local(idx): locals[idx]++
					fwrite($fhOut, "INCL [{$arg}]");
					break;
				case YaplOp::POP:
					fwrite($fhOut, "POP");
					break;
				case YaplOp::LAND: // LAND(): Logic AND
					fwrite($fhOut, "LAND");
					break;
				case YaplOp::LOR: // LOR(): Logic OR
					fwrite($fhOut, "LOR");
					break;
				case YaplOp::LNOT: // LNOT(): Logic NOT
					fwrite($fhOut, "LNOT");
					break;
				case YaplOp::STRGET: // STR_GET(): builtin call to 'str:get'
					fwrite($fhOut, "STR_GET // CALL str:get");
					break;
				case YaplOp::STRPRI: // STR_PRI(): builtin call to 'str:print'
					fwrite($fhOut, "STR_PRI // CALL str:print");
					break;
				case YaplOp::TPLSRC: // TPL_SRC(): builtin call to 'tpl:source'
					fwrite($fhOut, "TPL_SRC // CALL tpl:source");
					break;
				case YaplOp::TPLREAD: // TPL_READ(): builtin call to 'tpl:read'
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

	public function disassemble(string $name){
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
		$this->dasmBuffer($code_buf, $code_va, STDOUT);
		
	}

	public function __destruct(){
		if(is_resource($this->fh)){
			fclose($this->fh);
		}
	}
}