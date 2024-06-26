<?php

 
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * PHP ext/standard compatibility package
 *
 * @package		CodeIgniter
 * @subpackage	CodeIgniter
 * @category	Compatibility
 * @author		Andrey Andreev
 * @link		http://codeigniter.com/user_guide/
 */

// ------------------------------------------------------------------------

if (is_php('5.5'))
{
	return;
}

// ------------------------------------------------------------------------

if ( ! function_exists('array_column'))
{
	/**
	 * array_column()
	 *
	 * @link	http://php.net/array_column
	 * @param	string	$array
	 * @param	mixed	$column_key
	 * @param	mixed	$index_key
	 * @return	array
	 */
	function array_column(array $array, $column_key, $index_key = NULL)
	{
		if ( ! in_array($type = gettype($column_key), array('integer', 'string', 'NULL'), TRUE))
		{
			if ($type === 'double')
			{
				$column_key = (int) $column_key;
			}
			elseif ($type === 'object' && method_exists($column_key, '__toString'))
			{
				$column_key = (string) $column_key;
			}
			else
			{
				trigger_error('array_column(): The column key should be either a string or an integer', E_USER_WARNING);
				return FALSE;
			}
		}

		if ( ! in_array($type = gettype($index_key), array('integer', 'string', 'NULL'), TRUE))
		{
			if ($type === 'double')
			{
				$index_key = (int) $index_key;
			}
			elseif ($type === 'object' && method_exists($index_key, '__toString'))
			{
				$index_key = (string) $index_key;
			}
			else
			{
				trigger_error('array_column(): The index key should be either a string or an integer', E_USER_WARNING);
				return FALSE;
			}
		}

		$result = array();
		foreach ($array as &$a)
		{
			if ($column_key === NULL)
			{
				$value = $a;
			}
			elseif (is_array($a) && array_key_exists($column_key, $a))
			{
				$value = $a[$column_key];
			}
			else
			{
				continue;
			}

			if ($index_key === NULL OR ! array_key_exists($index_key, $a))
			{
				$result[] = $value;
			}
			else
			{
				$result[$a[$index_key]] = $value;
			}
		}

		return $result;
	}
}

// ------------------------------------------------------------------------

if (is_php('5.4'))
{
	return;
}

// ------------------------------------------------------------------------

if ( ! function_exists('hex2bin'))
{
	/**
	 * hex2bin()
	 *
	 * @link	http://php.net/hex2bin
	 * @param	string	$data
	 * @return	string
	 */
	function hex2bin($data)
	{
		if (in_array($type = gettype($data), array('array', 'double', 'object'), TRUE))
		{
			if ($type === 'object' && method_exists($data, '__toString'))
			{
				$data = (string) $data;
			}
			else
			{
				trigger_error('hex2bin() expects parameter 1 to be string, '.$type.' given', E_USER_WARNING);
				return NULL;
			}
		}

		if (strlen($data) % 2 !== 0)
		{
			trigger_error('Hexadecimal input string must have an even length', E_USER_WARNING);
			return FALSE;
		}
		elseif ( ! preg_match('/^[0-9a-f]*$/i', $data))
		{
			trigger_error('Input string must be hexadecimal string', E_USER_WARNING);
			return FALSE;
		}

		return pack('H*', $data);
	}
}

// ------------------------------------------------------------------------

if (is_php('5.3'))
{
	return;
}

// ------------------------------------------------------------------------

if ( ! function_exists('array_replace'))
{
	/**
	 * array_replace()
	 *
	 * @link	http://php.net/array_replace
	 * @return	array
	 */
	function array_replace()
	{
		$arrays = func_get_args();

		if (($c = count($arrays)) === 0)
		{
			trigger_error('array_replace() expects at least 1 parameter, 0 given', E_USER_WARNING);
			return NULL;
		}
		elseif ($c === 1)
		{
			if ( ! is_array($arrays[0]))
			{
				trigger_error('array_replace(): Argument #1 is not an array', E_USER_WARNING);
				return NULL;
			}

			return $arrays[0];
		}

		$array = array_shift($arrays);
		$c--;

		for ($i = 0; $i < $c; $i++)
		{
			if ( ! is_array($arrays[$i]))
			{
				trigger_error('array_replace(): Argument #'.($i + 2).' is not an array', E_USER_WARNING);
				return NULL;
			}
			elseif (empty($arrays[$i]))
			{
				continue;
			}

			foreach (array_keys($arrays[$i]) as $key)
			{
				$array[$key] = $arrays[$i][$key];
			}
		}

		return $array;
	}
}

// ------------------------------------------------------------------------

if ( ! function_exists('array_replace_recursive'))
{
	/**
	 * array_replace_recursive()
	 *
	 * @link	http://php.net/array_replace_recursive
	 * @return	array
	 */
	function array_replace_recursive()
	{
		$arrays = func_get_args();

		if (($c = count($arrays)) === 0)
		{
			trigger_error('array_replace_recursive() expects at least 1 parameter, 0 given', E_USER_WARNING);
			return NULL;
		}
		elseif ($c === 1)
		{
			if ( ! is_array($arrays[0]))
			{
				trigger_error('array_replace_recursive(): Argument #1 is not an array', E_USER_WARNING);
				return NULL;
			}

			return $arrays[0];
		}

		$array = array_shift($arrays);
		$c--;

		for ($i = 0; $i < $c; $i++)
		{
			if ( ! is_array($arrays[$i]))
			{
				trigger_error('array_replace_recursive(): Argument #'.($i + 2).' is not an array', E_USER_WARNING);
				return NULL;
			}
			elseif (empty($arrays[$i]))
			{
				continue;
			}

			foreach (array_keys($arrays[$i]) as $key)
			{
				$array[$key] = (is_array($arrays[$i][$key]) && isset($array[$key]) && is_array($array[$key]))
					? array_replace_recursive($array[$key], $arrays[$i][$key])
					: $arrays[$i][$key];
			}
		}

		return $array;
	}
}

// ------------------------------------------------------------------------

if ( ! function_exists('quoted_printable_encode'))
{
	/**
	 * quoted_printable_encode()
	 *
	 * @link	http://php.net/quoted_printable_encode
	 * @param	string	$str
	 * @return	string
	 */
	function quoted_printable_encode($str)
	{
		if (strlen($str) === 0)
		{
			return '';
		}
		elseif (in_array($type = gettype($str), array('array', 'object'), TRUE))
		{
			if ($type === 'object' && method_exists($str, '__toString'))
			{
				$str = (string) $str;
			}
			else
			{
				trigger_error('quoted_printable_encode() expects parameter 1 to be string, '.$type.' given', E_USER_WARNING);
				return NULL;
			}
		}

		if (function_exists('imap_8bit'))
		{
			return imap_8bit($str);
		}

		$i = $lp = 0;
		$output = '';
		$hex = '0123456789ABCDEF';
		$length = (extension_loaded('mbstring') && ini_get('mbstring.func_overload'))
			? mb_strlen($str, '8bit')
			: strlen($str);

		while ($length--)
		{
			if ((($c = $str[$i++]) === "\015") && isset($str[$i]) && ($str[$i] === "\012") && $length > 0)
			{
				$output .= "\015".$str[$i++];
				$length--;
				$lp = 0;
				continue;
			}

			if (
				ctype_cntrl($c)
				OR (ord($c) === 0x7f)
				OR (ord($c) & 0x80)
				OR ($c === '=')
				OR ($c === ' ' && isset($str[$i]) && $str[$i] === "\015")
			)
			{
				if (
					(($lp += 3) > 75 && ord($c) <= 0x7f)
					OR (ord($c) > 0x7f && ord($c) <= 0xdf && ($lp + 3) > 75)
					OR (ord($c) > 0xdf && ord($c) <= 0xef && ($lp + 6) > 75)
					OR (ord($c) > 0xef && ord($c) <= 0xf4 && ($lp + 9) > 75)
				)
				{
					$output .= "=\015\012";
					$lp = 3;
				}

				$output .= '='.$hex[ord($c) >> 4].$hex[ord($c) & 0xf];
				continue;
			}

			if ((++$lp) > 75)
			{
				$output .= "=\015\012";
				$lp = 1;
			}

			$output .= $c;
		}

		return $output;
	}
}
