<?php declare(strict_types=1);
/**
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * @license AGPL-3.0-or-later
 * @author KampfCaspar <code@kampfcaspar.ch>
 */

namespace KampfCaspar\JWT\WebToken;

use KampfCaspar\JWT\JWT;
use KampfCaspar\JWT\JWTDecoderInterface;
use KampfCaspar\JWT\JWTDecoderTrait;
use KampfCaspar\JWT\JWTEncoderInterface;
use KampfCaspar\JWT\JWTSerializerEnum;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;

/**
 * Nested JWT Creation and Consumption Frontend
 *
 * Abstraction class that either creates a nested JWT (encodes) from a given payload or
 * verifies and consumes (decrypts) a nested JWT and returns the payload.
 */
class NestedCoder implements LoggerAwareInterface, JWTEncoderInterface, JWTDecoderInterface
{
	use JWTDecoderTrait;
	use LoggerAwareTrait;

	/** instantiate the nested token code
	 * @param JWECoder $jweCoder
	 * @param JWSCoder $jwsCoder
	 */
	public function __construct(
		private readonly JWECoder $jweCoder,
		private readonly JWSCoder $jwsCoder,
	) {}

	/**
	 * @inheritdoc
	 */
	public function encode(
		array|JWT|string $payload,
		array $header = [],
		array|string|null $additionalKeys = null,
		?JWTSerializerEnum $serializer = null
	): string
	{
		$jws_str = $this->jwsCoder->encode($payload);
		$jwe_str = $this->jweCoder->encode(
			$jws_str,
			['cty' => 'JWT'] + $header,
			$additionalKeys,
			$serializer
		);
		return $jwe_str;
	}

	/**
	 * @throws \Exception
	 */
	public function decodeBinary(string $token): array
	{
		$jwe = $this->jweCoder->_decodeObject($token);
		if ($jwe->getSharedProtectedHeaderParameter('cty') != 'JWT') {
			throw new \InvalidArgumentException('Not a nested JWT token');
		}
		$payload = $jwe->getPayload();
		if (is_null($payload)) {
			throw new \InvalidArgumentException('nested token is not nested');
		}
		$jws = $this->jwsCoder->_decodeObject($payload);
		return [
			$jws->getPayload() ?? '',
			$jws->getSignature(0)->getProtectedHeader(),
		];
	}
}