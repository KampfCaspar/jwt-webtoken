<?php

namespace KampfCaspar\Test\JWT\WebToken\Fixtures;

use KampfCaspar\JWT\JWT;
use KampfCaspar\JWT\JWTSerializerEnum;
use KampfCaspar\JWT\WebToken\AbstractCoder;
class AbstractCoderFixture extends AbstractCoder
{
	public function addSerializer(JWTSerializerEnum $serializer): static
	{
		return $this;
	}

	public function decodeBinary(string $token): array
	{
		return $this;
	}

	public function encode(array|JWT|string $payload, array $header = [], array|string|null $additionalKeys = null, ?JWTSerializerEnum $serializer = null): string
	{
		return '';
	}

}