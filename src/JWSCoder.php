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

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use KampfCaspar\JWT\JWT;
use KampfCaspar\JWT\JWTSerializerEnum;

/**
 * JWS Creation and Consumption Frontend
 *
 * Abstraction class that either creates a JWS (encodes) from a given payload or
 * verifies and consumes (decrypts) a JWS and returns the payload.
 */
class JWSCoder extends AbstractCoder
{
	/** map of official signature algorithm names to web-token class names
	 * @see self::addAlgorithms()
	 */
	protected const ALGORITHM_MAP_SIGNATURE = [
		'ES256' => 'Jose\Component\Signature\Algorithm\ES256',
		'ES384' => 'Jose\Component\Signature\Algorithm\ES384',
		'ES512' => 'Jose\Component\Signature\Algorithm\ES512',
		'EdDSA' => 'Jose\Component\Signature\Algorithm\EdDSA',
		'BLAKE2B' => 'Jose\Component\Signature\Algorithm\Blake2b',
		'ES256K' => 'Jose\Component\Signature\Algorithm\ES256K',
		'HS1' => 'Jose\Component\Signature\Algorithm\HS1',
		'HS256/64' => 'Jose\Component\Signature\Algorithm\HS256_64',
		'RS1' => 'Jose\Component\Signature\Algorithm\RS1',
		'HS256' => 'Jose\Component\Signature\Algorithm\HS256',
		'HS384' => 'Jose\Component\Signature\Algorithm\HS384',
		'HS512' => 'Jose\Component\Signature\Algorithm\HS512',
		'PS256' => 'Jose\Component\Signature\Algorithm\PS256',
		'PS384' => 'Jose\Component\Signature\Algorithm\PS384',
		'PS512' => 'Jose\Component\Signature\Algorithm\PS512',
		'RS256' => 'Jose\Component\Signature\Algorithm\RS256',
		'RS384' => 'Jose\Component\Signature\Algorithm\RS384',
		'RS512' => 'Jose\Component\Signature\Algorithm\RS512',
		'none' => 'Jose\Component\Signature\Algorithm\None',
	];

	/** all signature algorithms added
	 * @see self::addAlgorithms()
	 * @var array<Algorithm>
	 */
	protected array $algorithms = [];

	/** all serializers added for decoding
	 * @see self::decode()
	 * @var array<JWSSerializer>
	 */
	protected array $serializers = [];

	protected JWSBuilder $jwsBuilder;

	protected JWSLoader $jwsLoader;

	/**
	 * add one or many signature algorithms to support
	 *
	 * @param string|iterable<string> $algorithms
	 *
	 * @throws \InvalidArgumentException  if an algorithm cannot be found
	 */
	public function addAlgorithms(string|Iterable $algorithms) : static
	{
		array_push($this->algorithms, ...$this->createAlgorithms(static::ALGORITHM_MAP_SIGNATURE, $algorithms));
		unset($this->jwsLoader);  // both loader and builder consume the list of algorithms
		unset($this->jwsBuilder);
		return $this;
	}

	/**
	 * add a serializer to the collection of supported serializers for decoding
	 */
	public function addSerializer(JWTSerializerEnum $serializer) : static
	{
		$this->serializers[$serializer->name] = match($serializer) {
			JWTSerializerEnum::COMPACT => new CompactSerializer(),
			JWTSerializerEnum::FLATTENED => new JSONFlattenedSerializer(),
			JWTSerializerEnum::JSON => new JSONGeneralSerializer(),
		};
		unset($this->jwsLoader); // loader consumes the list of serializers
		return $this;
	}

	/**
	 * create a SerializerManager with the collected serializers for decoding
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _createSerializerManager(): JWSSerializerManager
	{
		if (!count($this->serializers)) {
			$this->addSerializer($this->defaultSerializer);
		}
		return new JWSSerializerManager($this->serializers);
	}

	/**
	 * get (and create) a JWSBuilder
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _getJWSBuilder(): JWSBuilder
	{
		if (!isset($this->jwsBuilder)) {
			$this->jwsBuilder = new JWSBuilder(
				new AlgorithmManager($this->algorithms)
			);
		}
		return $this->jwsBuilder;
	}

	/**
	 * get (and create) a JWSLoader
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _getJWSLoader(): JWSLoader
	{
		if (!isset($this->jwsLoader)) {
			$manager = new AlgorithmManager($this->algorithms);
			$this->jwsLoader = new JWSLoader(
				$this->_createSerializerManager(),
				new JWSVerifier($manager),
				new HeaderCheckerManager(
					[
						new AlgorithmChecker($manager->list())
					],
					[
						new JWSTokenSupport()
					]
				)
			);
		}
		return $this->jwsLoader;
	}

	/**
	 * @inheritdoc
	 */
	public function encode(
		array|JWT|string $payload,
		array $header = [],
		array|string|null $additionalKeys = null,
		?JWTSerializerEnum $serializer = null): string
	{
		$keys = $this->getKeyIterator($additionalKeys);
		[$payload_binary, $header_source] = $this->getEncodingPayload($payload);

		$builder = $this->_getJWSBuilder()
			->create()
			->withPayload($payload_binary);

		foreach ($keys as $key) {
			if (!$this->canKeyUsage($key, 'sign')) {
				continue;
			}
			$foundAlg = false;
			foreach ($this->algorithms as $alg) {
				if ($this->canKeyAlgorithm($key, $alg)) {
					$foundAlg = true;
					break;
				}
			}
			if (!$foundAlg) {
				continue;
			}
			$builder = $builder->addSignature(
				$key,
				['alg' => $alg->name()] + $header + $header_source // @phpstan-ignore-line
			);
			// @phpstan-ignore-next-line as $alg IS set
			$this->logAlgorithmKeyCheck($alg, $key);

			if (!$this->encodeToMany) {
				break;
			}
		}
		$jws = $builder->build();

		if (!$jws->countSignatures()) {
			throw new \DomainException('no compatible key and algorithm found');
		}

		$serializer = $serializer ?? ($this->encodeToMany ? JWTSerializerEnum::JSON : $this->defaultSerializer);
		if (!isset($this->serializers[$serializer->name])) {
			$this->addSerializer($serializer);
		}
		return $this->serializers[$serializer->name]->serialize($jws);
	}

	/**
	 * decode and return JWS
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _decodeObject(string $token): JWS
	{
		try {
			$jws = $this->_getJWSLoader()
				->loadAndVerifyWithKeySet($token, new JWKSet($this->decodeKeys), $signature);
		}
		catch (\Throwable $e) {
			throw new \InvalidArgumentException('invalid JWS given', $e->getCode(), $e);
		}
		return $jws;
	}

	/**
	 * @inheritdoc
	 */
	public function decodeBinary(string $token): array
	{
		$jws = $this->_decodeObject($token);
		return [
			$jws->getPayload() ?? '',
			$jws->getSignature(0)->getProtectedHeader()
		];
	}

}