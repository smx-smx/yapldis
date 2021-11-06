<?php
/**
  * @author Stefano Moioli
  * @copyright 2021 Stefano Moioli
  * @license https://opensource.org/licenses/Zlib
  */

namespace Smx\Utils;

use stdClass;

class Struct {
	public static function makeDef(array $fields){
		$arr = array();
		foreach($fields as $name => $type){
			$arr[] = "{$type}{$name}";
		}
		$def = implode('/', $arr);
		return $def;
	}

	private string $def;
	private int $size;

    private static function determineSize(array $fields){
        $size = 0;
        foreach($fields as $_ => $type){
            try {
                $pack = pack($type, 0);
                $size += strlen($pack);
            } catch(\Error $_){
                throw new \InvalidArgumentException("Cannot detemine size for type '{$type}', specify size manually");
            }
        }
        return $size;
    }
    
	public function __construct(array $fields, ?int $size = null){
		$this->def = self::makeDef($fields);
        if($size !== null){
            $this->size = $size;
        } else {
            $this->size = self::determineSize($fields);
        }
	}

    private static function unpack(string $def, string $data, int $offset = 0){
        $result = \unpack($def, $data, $offset);
        $obj = new stdClass;
        foreach($result as $key => $value){
            $obj->{$key} = $value;
        }
        return $obj;
    }

	public function fromStream($fh){
		$data = fread($fh, $this->size);
		return self::unpack($this->def, $data);
	}

	public function fromData(string $data){
		return self::unpack($this->def, $data);
	}
}
