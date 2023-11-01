<?php

namespace KampfCaspar\Test\JWT\WebToken;

use KampfCaspar\JWT\JWTSerializerEnum;
use KampfCaspar\JWT\WebToken\JWECoder;
use KampfCaspar\JWT\WebToken\JWSCoder;
use KampfCaspar\JWT\WebToken\JWSEncoder;
use KampfCaspar\JWT\WebToken\NestedCoder;

class NestedCoderTest extends AbstractCoderCase
{
	protected const TOKENS_NESTED = [
		'HS1' => 'eyJpdiI6ImFtZmczNzlfT040Y2lBLXIiLCJ0YWciOiIyWFlhUGxLNnVVckoyRHZGbERENFV3IiwiZW5jIjoiQTEyOEdDTSIsInppcCI6IkRFRiIsImFsZyI6IkExMjhHQ01LVyIsImN0eSI6IkpXVCJ9.sQJQj3nzO4JGMjYcjvRtsA.r8WQQFONnblDhXC1.4WEekML2aU6js1UkuogPdmSnbbCHAObXNivVygGHJd1x_iB0EJPsw-pTsbdgmWO5D7urKKo8tR842zPmDyjyYYlyxOrJOMx3JFPRxFs1Moq9rU9N-f9sEH546Mn-dRIYgyzhZktO-80OOnNq6V5qKNgc2gs.LQU1yAJ3oeFw1ppbzT1zfw',
	];

	public function testEncodeDefault(): void
	{
		$this->expectNotToPerformAssertions();
		$jwtHandler = new NestedCoder(
			(new JWECoder())
				->addKeyEncryptionAlgorithms('A128GCMKW')
				->addContentEncryptionAlgorithms('A128GCM')
				->addKeys(static::KEYS['oct'])
				->addSerializer(JWTSerializerEnum::COMPACT),
			(new JWSCoder())
			->addAlgorithms('HS1')
			->addKeys(static::KEYS['oct'])
			->addSerializer(JWTSerializerEnum::COMPACT)
		);
		$token = $jwtHandler->encode(static::PAYLOAD);
	}

	public function testDecodeDefault(): void
	{
		$jwtHandler = new NestedCoder(
			(new JWECoder())
				->addKeyEncryptionAlgorithms('A128GCMKW')
				->addContentEncryptionAlgorithms('A128GCM')
				->addKeys(static::KEYS['oct'])
				->addSerializer(JWTSerializerEnum::COMPACT),
			(new JWSCoder())
				->addAlgorithms('HS1')
				->addKeys(static::KEYS['oct'])
				->addSerializer(JWTSerializerEnum::COMPACT)
		);
		$payload = $jwtHandler->decode(static::TOKENS_NESTED['HS1']);
		$this->assertEquals(static::PAYLOAD, $payload);
	}

}
