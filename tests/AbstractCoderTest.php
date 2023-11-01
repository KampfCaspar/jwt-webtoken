<?php

namespace KampfCaspar\Test\JWT\WebToken;

use KampfCaspar\Test\JWT\WebToken\Fixtures\AbstractCoderFixture;

class AbstractCoderTest extends AbstractCoderCase
{
	public function testAddKeys(): void
	{
		$this->expectNotToPerformAssertions();
		$jwtHandler = (new AbstractCoderFixture())->addKeys(static::KEYS['EC']);
		$jwtHandler = (new AbstractCoderFixture())->addKeys([
			'keys' => [
				static::KEYS['RSA'],
				static::KEYS['oct'],
			]
		]);
		$jwtHandler = (new AbstractCoderFixture())->addKeys([
			static::KEYS['RSA'],
			static::KEYS['oct'],
		]);
		$jwtHandler = (new AbstractCoderFixture())->addKeys(json_encode(static::KEYS['EC']));
	}

	public function testAddKeysInvalidKey(): void
	{
		$this->expectException(\Exception::class);
		$jwtHandler = (new AbstractCoderFixture())->addKeys(['d'=> '123']);
	}

	public function testAddKeysInvalidJSON(): void
	{
		$this->expectException(\Exception::class);
		$jwtHandler = (new AbstractCoderFixture())->addKeys('abc');
	}


}
