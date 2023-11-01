<?php

namespace KampfCaspar\Test\JWT\WebToken;

use KampfCaspar\JWT\JWTSerializerEnum;
use KampfCaspar\JWT\WebToken\JWECoder;

class JWECoderTest extends AbstractCoderCase
{
	protected const TOKENS_JWE = [
		'AES' => 'eyJpdiI6IkFFM0d5RXRKMFJTbFdJLW0iLCJ0YWciOiJlOWZ5R3FxdDlEeFZOQnBfX01WdEdnIiwiZW5jI' .
			'joiQTEyOEdDTSIsInppcCI6IkRFRiIsImFsZyI6IkExMjhHQ01LVyJ9.e4conhfYZ8cMpVhsRCR3XQ.' .
			'j3foFDb1ep4sOB-Q.8n9IKo3UUgk3qid5rTYFjyuhElysvCY7zQuSMLJ79pQZC8JPMdBPzmg.' .
			'dfAWxpeI-JHp59vkt8xaQA',
		'ECRS' => '{"ciphertext":"9_dMDjvcfVze-bjsK0G0Om9ULgqLSJFWNyTrPLWKDJH6fR-G1UuKOTI",' .
			'"iv":"AxrwDBjcUSIkywXx","tag":"MwJPLh3nwxGPyDFPuhvU8Q","protected":'.
			'"eyJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0","recipients":[{"header":{"alg":' .
			'"ECDH-ES+A128KW","epk":{"kty":"EC","crv":"P-256","x":"gIKKT_gkF89y95zb-mHKN9yVkpZt' .
			'-gBiSE2dzOf5pDQ","y":"hTnQwUNQ8YJvT3U4fZf4ld8y1MnPSRCcyA5CStKxgSI"}},"encrypted_key"' .
			':"SyYexsOAqHdGh5lXwGmjqPp8ty7Zsg0k"},{"header":{"alg":"RSA1_5"},"encrypted_key":'.
			'"EsiwwBwYUvE1N87Mcbu3v1V4O0o0aHxpR8EywRxi8k76jO0Cj074FHoh4xn_kI4E6VeRzdDZv9-' .
			'ovDmr67DABQ"}]}',
	];

	protected function _validateCompactToken(string $token, string $keyAlg, string $contentAlg): void
	{
		$parts = explode('.', $token);
		$this->assertCount(5, $parts);
		$header = json_decode(base64_decode($parts[0], true), true);
		$this->assertIsArray($header);
		$this->assertEquals($keyAlg, $header['alg'] ?? null);
		$this->assertEquals($contentAlg, $header['enc'] ?? null);
	}

	protected function _validateJSONToken(string $token, array $keyAlgs, string $contentAlg, bool $flattened = false): void
	{
		$parts = json_decode($token, true, JSON_THROW_ON_ERROR);
		$this->assertArrayHasKey('ciphertext', $parts);
		$this->assertArrayHasKey('protected', $parts);
		$protected = json_decode(base64_decode($parts['protected']), true, JSON_THROW_ON_ERROR);
		$this->assertEquals($contentAlg, $protected['enc']);
		if ($flattened) {
			$this->assertArrayHasKey('header', $parts);
			$recipients = $parts;
		}
		else {
			$this->assertArrayHasKey('recipients', $parts);
			$this->assertCount(count($keyAlgs), $parts['recipients']);
			$recipients = $parts['recipients'];
		}
		foreach ($recipients as $recipient) {
			$should = array_shift($keyAlgs);
			$is = $recipient['header']['alg'];
			$this->assertEquals($should, $is);
		}
	}

	public function testAddKeyEncryptionAlgorithms(): void
	{
		$jwtHandler = new JWECoder();
		$res = $jwtHandler->addKeyEncryptionAlgorithms('A128GCMKW');
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addKeyEncryptionAlgorithms(['A128KW','dir']);
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addKeyEncryptionAlgorithms( new \ArrayObject(['ECDH-ES+A128KW','RSA1_5']));
		$this->assertSame($jwtHandler, $res);
		$this->expectException(\InvalidArgumentException::class);
		$jwtHandler->addKeyEncryptionAlgorithms('WRONG');
	}

	public function testAddContentEncryptionAlgorithms(): void
	{
		$jwtHandler = new JWECoder();
		$res = $jwtHandler->addContentEncryptionAlgorithms('A128CBC-HS256');
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addContentEncryptionAlgorithms(['A128GCM','A192CBC-HS384']);
		$this->assertSame($jwtHandler, $res);
		$res = $jwtHandler->addContentEncryptionAlgorithms( new \ArrayObject(['A256GCM','A256CBC-HS512']));
		$this->assertSame($jwtHandler, $res);
		$this->expectException(\InvalidArgumentException::class);
		$jwtHandler->addContentEncryptionAlgorithms('WRONG');
	}

	public function testEncodeDefault(): void
	{
		$jwtHandler = (new JWECoder())
			->addKeyEncryptionAlgorithms('A128GCMKW')
			->addContentEncryptionAlgorithms('A128GCM')
			->addKeys(static::KEYS['oct']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'A128GCMKW', 'A128GCM'); // simple 1/1
		$jwtHandler->addKeyEncryptionAlgorithms('dir');
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'A128GCMKW', 'A128GCM'); // multiple algorithms
		$jwtHandler->addKeys(static::KEYS['RSA']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'A128GCMKW', 'A128GCM'); // multiple algorithms / multiple keys

		$jwtHandler = (new JWECoder())
			->addKeyEncryptionAlgorithms(['ECDH-ES+A128KW', 'dir'])
			->addContentEncryptionAlgorithms('A128GCM')
			->addKeys(static::KEYS['RSA'])
			->addKeys(static::KEYS['oct']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateCompactToken($token, 'dir', 'A128GCM'); // not first combination of algo/key
	}

	public function testEncodeIncompatibleKeyAlgorithm(): void
	{
		$jwtHandler = (new JWECoder())
			->addKeyEncryptionAlgorithms(['ECDH-ES+A128KW', 'dir'])
			->addContentEncryptionAlgorithms('A128GCM')
			->addKeys(static::KEYS['RSA']);
		$this->expectException(\Exception::class);
		$token = $jwtHandler->encode(static::PAYLOAD);
	}

	public function testEncodeToMany(): void
	{
		$jwtHandler = (new JWECoder())
			->setEncodeToMany(true)
			->addKeyEncryptionAlgorithms(['ECDH-ES+A128KW', 'RSA1_5'])
			->addContentEncryptionAlgorithms('A128GCM')
			->addKeys(static::KEYS['EC'])
			->addKeys(static::KEYS['RSA']);
		$token = $jwtHandler->encode(static::PAYLOAD);
		$this->_validateJSONToken($token, ['ECDH-ES+A128KW', 'RSA1_5'], 'A128GCM');
	}

	public function testDecodeDefault(): void
	{
		$jwtHandler = (new JWECoder())
			->addKeyEncryptionAlgorithms(['A128GCMKW', 'ECDH-ES+A128KW', 'RSA1_5'])
			->addContentEncryptionAlgorithms('A128GCM')
			->addKeys(static::KEYS['EC'])
			->addKeys(static::KEYS['RSA'])
			->addKeys(static::KEYS['oct'])
			->addSerializer(JWTSerializerEnum::COMPACT)
			->addSerializer(JWTSerializerEnum::JSON);

		$jwe = $jwtHandler->decode(static::TOKENS_JWE['ECRS']);
		$this->assertEquals(static::PAYLOAD, $jwe);
		$jwe = $jwtHandler->decode(static::TOKENS_JWE['AES']);
		$this->assertEquals(static::PAYLOAD, $jwe);
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
