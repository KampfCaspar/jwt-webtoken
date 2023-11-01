<?php

namespace KampfCaspar\Test\JWT\WebToken;

use KampfCaspar\JWT\JWTSerializerEnum;
use KampfCaspar\JWT\WebToken\JWSCoder;
use KampfCaspar\JWT\WebToken\JWSEncoder;

class JWSCoderTest extends AbstractCoderCase
{
	protected const TOKENS_JWS = [
		'ES' => 'eyJhbGciOiJFUzI1NiJ9.' .
			'eyJhbHBoYSI6ImJldGEiLCJnYW1tYSI6MCwiZGVsdGEiOlsiYWxwaGEiLCJiZXRhIiwiZ2FtbWEiXX0.' .
			'T89Wg_C5h00fqMYG8KimK3JF4NePsPu3keM6YWDzdZWYfG1XAOFJ0DCPKE5HlTXvN2K8kAabjsSaTGuG8DrOZQ',
		'RSES' => '{"payload":"eyJhbHBoYSI6ImJldGEiLCJnYW1tYSI6MCwiZGVsdGEiOlsiYWxwaGEiLCJiZXRhIiwi' .
			'Z2FtbWEiXX0","signatures":[{"signature":"KMX-3LGRpyIO7DTy0GFalS9m8U-I7eG80vFz-' .
			'KR352YEiJ6Huafbz9lQrHOHVPThPUF4LkFZWNc_ECGEmBx0pA","protected":"eyJhbGciOiJSUz' .
			'I1NiJ9"},{"signature":"4ghY-VgRC97-F07rU8rw8UHAD3V7H5HOKNSjMxGpiheRSJwX74iOrb3' .
			'3Hq2EHWtrtfabNaEnf5sZZijk6NyxSg","protected":"eyJhbGciOiJFUzI1NiJ9"}]}',
	];

	protected function _validateCompactToken(string $token, string $alg): void
	{
		$parts = explode('.', $token);
		$this->assertCount(3, $parts);
		$header = json_decode(base64_decode($parts[0], true), true);
		$this->assertIsArray($header);
		$this->assertEquals($alg, $header['alg'] ?? null);
		$body = json_decode(base64_decode($parts[1], true), true);
		$this->assertEquals(static::PAYLOAD, $body);
	}

	protected function _validateJSONToken(string $token, array $algs, bool $flattened = false): void
	{
		$parts = json_decode($token, true, JSON_THROW_ON_ERROR);
		$this->assertArrayHasKey('payload', $parts);
		if ($flattened) {
			$this->assertArrayHasKey('protected', $parts);
			$signatures = $parts;
		}
		else {
			$this->assertArrayHasKey('signatures', $parts);
			$this->assertCount(count($algs), $parts['signatures']);
			$signatures = $parts['signatures'];
		}
		foreach ($signatures as $sig) {
			$should = array_shift($algs);
			$is = json_decode(base64_decode($sig['protected']), true, JSON_THROW_ON_ERROR)['alg'];
			$this->assertEquals($should, $is);
		}

		$payload = json_decode(base64_decode($parts['payload']), true, JSON_THROW_ON_ERROR);
		$this->assertEquals(static::PAYLOAD, $payload);
	}

	public function testAddAlgorithm(): void
	{
		$jwtHandler = new JWSCoder();
		$res = $jwtHandler->addAlgorithms('ES256');
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addAlgorithms(['HS256','ES512']);
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addAlgorithms( new \ArrayObject(['PS256','none']));
		$this->assertSame($jwtHandler, $res);
		$this->expectException(\InvalidArgumentException::class);
		$jwtHandler->addAlgorithms('WRONG');
	}

	public function testEncodeDefault(): void
	{
		$jwtHandler = (new JWSCoder())
			->addAlgorithms('ES256')
			->addKeys(static::KEYS['EC']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'ES256'); // simple 1/1
		$jwtHandler->addAlgorithms('PS256');
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'ES256'); // multiple algorithms
		$jwtHandler->addKeys(static::KEYS['RSA']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'ES256'); // multiple algorithms / multiple keys

		$jwtHandler = (new JWSCoder())
			->addAlgorithms(['ES256', 'RS256'])
			->addKeys(static::KEYS['oct'])
			->addKeys(static::KEYS['RSA']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'RS256'); // not first combination of algo/key
	}

	public function testEncodeIncompatibleKeyAlgorithm(): void
	{
		$jwtHandler = (new JWSCoder())
			->addAlgorithms('ES256')
			->addKeys(static::KEYS['RSA']);
		$this->expectException(\Exception::class);
		$token = $jwtHandler->encode(static::PAYLOAD);
	}

	public function testEncodeToMany(): void
	{
		$jwtHandler = (new JWSCoder())
			->setEncodeToMany(true)
			->addAlgorithms(['ES256','RS256'])
			->addKeys([static::KEYS['RSA'], static::KEYS['EC']]);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateJSONToken($token, ['RS256', 'ES256']); // not first combination of algo/key
	}

	public function testDecodeDefault(): void
	{
		$jwtHandler = (new JWSCoder())
			->addAlgorithms(['ES256','RS256'])
			->addKeys(static::KEYS['EC'])
			->addSerializer(JWTSerializerEnum::COMPACT)
			->addSerializer(JWTSerializerEnum::JSON);

		$jws = $jwtHandler->decode(static::TOKENS_JWS['ES']);
		$this->assertEquals(static::PAYLOAD, $jws);
		$jws = $jwtHandler->decode(static::TOKENS_JWS['RSES']);
		$this->assertEquals(static::PAYLOAD, $jws);
	}

//	public function testSetDefaultSerializer()
//	{
//
//	}
//
//	public function testAddEncodeKey()
//	{
//
//	}

}
