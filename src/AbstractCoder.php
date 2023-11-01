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

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\JWK;
use KampfCaspar\JWT\JWTDecoderInterface;
use KampfCaspar\JWT\JWTDecoderTrait;
use KampfCaspar\JWT\JWTEncoderInterface;
use KampfCaspar\JWT\JWTEncoderTrait;
use KampfCaspar\JWT\JWTSerializerEnum;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;

/**
 * Abstract Base Class for JWS and JWE Coders
 *
 * Coders are prepared with:
 *   - add supported algorithms (signature algorithms for JWS, key and content encryption for JWE)
 *   - add keys (either for both decoding and encoding or separately)
 *   - add supported serializers (for decoding only)
 *   - (optional) allow encoding to multiple keys
 *   - (optional) set a default serializer for encoding to single key
 *
 * After setup, one can create or consume a JWT
 *   - {@see JWTDecoderInterface::decode()} for creation of the JWT
 *   - {@see JWTEncoderInterface::encode()} for consumation of a JWT into an array
 */
abstract class AbstractCoder implements LoggerAwareInterface, JWTDecoderInterface, JWTEncoderInterface
{
	use JWTDecoderTrait, JWTEncoderTrait;
	use LoggerAwareTrait;

	/** JWK used to decode
	 * @see self::addKeys()
	 * @var array<JWK>
	 */
	protected array $decodeKeys = [];

	/** JWK to encode to
	 * @see self::addEncodeKeys()
	 * @var array<JWK>
	 */
	protected array $encodeKeys = [];

	/** whether to encode to more than one signature/recipient
	 * @see self::setEncodeToMany()
	 */
	protected bool $encodeToMany = false;

	/** serializer to use with single signature/recipient
	 * @see self::setDefaultSerializer()
	 */
	protected JWTSerializerEnum $defaultSerializer = JWTSerializerEnum::COMPACT;

	/**
	 * add one or more JWK to use for decoding (and subsidiarily encoding)
	 *
	 * Accepted key material may be either in JSON format or as PHP Iterable:
	 *   - single key (JWK)
	 *   - JWKset (dictionary with attribute 'keys' containing an array of JWKs)
	 *   - Iterable of keys (JWKs)
	 *
	 * @param string|Iterable<mixed> $key
	 *
	 * @throws \InvalidArgumentException  if key cannot be interpreted
	 */
	public function addKeys(string|Iterable $key) : static
	{
		array_push($this->decodeKeys, ...$this->createJWKArray($key));
		return $this;
	}

	/**
	 * add one or more JWK to use specifically for encoding
	 *
	 * If no keys are added specifically for encoding, the common (decoding) keys are used.
	 *
	 * @see self::addKeys()
	 *
	 * @param string|Iterable<mixed> $key
	 *
	 * @throws \InvalidArgumentException  if key cannot be interpreted
	 */
	public function addEncodeKeys(string|Iterable $key) : static
	{
		array_push($this->encodeKeys, ...$this->createJWKArray($key));
		return $this;
	}

	/**
	 * allow encoding to multiple keys (either signatures or encryption recipients)
	 *
	 * By default, Coders stop after finding the first valid algorithm/key combination;
	 * resulting in only one signature or one recipient. If enabled, all keys are checked,
	 * allowing the creation of multiple signatures / encryption recipients.
	 */
	public function setEncodeToMany(bool $many = true): static
	{
		$this->encodeToMany = $many;
		return $this;
	}

	/**
	 * set serializer to use in case of single signatures/recipients
	 *
	 * JWT with only a single signature / one recipient may be encoded either in
	 * `Compact`, `Flattened JSON`, `General JSON` format.
	 *  While we default to `Compact` or token format, a different default serializer
	 *  might be selected.
	 */
	public function setDefaultSerializer(JWTSerializerEnum $serializer): static
	{
		$this->defaultSerializer = $serializer;
		return $this;
	}

	/**
	 * add a serializer to support for encoding
	 *
	 * For decoding, all supported serializers have to be added beforehand. If this
	 * step is left out, the default serializer ({@see self::setDefaultSerializer()})
	 * is instantiated.
	 */
	abstract public function addSerializer(JWTSerializerEnum $serializer) : static;

	/**
	 * @inheritdoc
	 */
	abstract public function decodeBinary(string $token): string;

	/**
	 * @inheritdoc
	 */
	abstract public function encodeBinary(
		string $payload,
		array $header = [],
		array|string|null $additionalKeys = null,
		?JWTSerializerEnum $serializer = null): string;

	///// Below this line only internal support methods

	/**
	 * create one or several named algorithm objects
	 *
	 * @param array<string,string>     $map    dictionary mapping algorithm names to classes
	 * @param string|Iterable<string>  $names  one or several names of algorithms to instantiate
	 * @return array<Algorithm>                the created algorithm objects
	 *
	 * @throws \InvalidArgumentException       if algorithm or its class not found
	 */
	protected function createAlgorithms(array $map, string|Iterable $names): array
	{
		$res = [];
		if (is_string($names)) {
			$names = (array)$names;
		}
		try {
			foreach ($names as $alg) {
				$class = $map[$alg] ?? null;
				if ($class) {
					/** @var Algorithm $algorithm */
					$algorithm = new ($class)();
					$res[] = $algorithm;
				}
				else {
					throw new \InvalidArgumentException(sprintf('unknown algorithm "%s"', $alg));
				}
			}
		}
		catch (\Error $e) {
			// @phpstan-ignore-next-line as $alg is always set
			throw new \InvalidArgumentException(sprintf('algorithm "%s" seems not to be loadable', $alg), 0, $e);
		}
		return $res;
	}

	/**
	 * create an array of JWK out of all accepted key material
	 *
	 * @param string|Iterable<mixed>  $rawKey
	 * @return array<JWK>
	 *
	 * @throws \InvalidArgumentException  if key cannot be interpreted
	 */
	protected function createJWKArray(string|Iterable $rawKey): array
	{
		if (is_string($rawKey)) {
			try {
				$rawKey = json_decode($rawKey, true,
					512, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);;
			}
			catch (\JsonException $e) {  // \JsonException does not conform to SPL hierarchy
				throw new \InvalidArgumentException('string JWT key or keyset must be valid json', $e->getCode(), $e);
			}
		}
		if ((is_array($rawKey) || $rawKey instanceof \ArrayAccess) && isset($rawKey['keys'])) {
				$rawKey = $rawKey['keys'];
		}
		if (is_array($rawKey) && !array_is_list($rawKey)) {
			$rawKey = [$rawKey];
		}

		$res = [];
		foreach ($rawKey as $key) {
			$res[] = new JWK($key); // might throw \InvalidArgumentException
		}
		return $res;
	}

	/**
	 * check if a JWK supports a key usage
	 *
	 * Key usage is one of:
	 *   - sign / verify
	 *   - encrypt / decrypt
	 *   - wrapKey / unwrapKeu
	 *
	 * Both `use` and `key_ops` claims are checked.
	 *
	 * @throws \InvalidArgumentException  if called with wrong usage parameter
	 */
	protected function canKeyUsage(JWK $key, string $usage): bool
	{
		$res = true;
		if ($key->has('use')) {  // first test, so $res is true
			$res = match ($usage) {
				'sign', 'verify' => $key->get('use') == 'sig',
				'encrypt', 'decrypt', 'wrapKey', 'unwrapKey' => $key->get('use') == 'enc',
				default => throw new \InvalidArgumentException(sprintf('unknown usage "%s"', $usage)),
			};
		}
		if ($res && $key->has('key_ops')) {
			$res = in_array( $usage, $key->get('key_ops'), true);
		}
		return $res;
	}

	/**
	 * check if a given key is compatible with a given algorithm
	 *
	 * Both an algorithm specification in the key and key type support of the algorithm
	 * are checked.
	 */
	protected function canKeyAlgorithm(JWK $key, Algorithm $algorithm): bool
	{
		$res = true;
		if ($key->has('alg')) {  // first test, $res is true
			$res = $key->get('alg') == $algorithm->name();
		}
		if ($res) {
			$allowed_kty = $algorithm->allowedKeyTypes();
			if ($allowed_kty) {
				$res = in_array($key->get('kty'), $allowed_kty , true);
			}
		}
		return $res;
	}

	/**
	 * log deprecated/unsafe algorithms and unsafe algorithm/key combinations
	 *
	 * @see https://web-token.spomky-labs.com/the-components/signed-tokens-jws/signature-algorithms
	 * @see https://web-token.spomky-labs.com/the-components/encrypted-tokens-jwe/encryption-algorithms
	 */
	protected function logAlgorithmKeyCheck(Algorithm $algorithm, JWK $key) : void
	{
		if (isset($this->logger)) {
			$alg = $algorithm->name();
			$kty = $key->get('kty');

			if (in_array($alg, ['RS1', 'HS1', 'ES256K', 'RSA1_5'])) {
				$this->logger->warning('JWT algorithm "{alg}" is deprecated.', [
					'alg' => $alg
				]);
			}
			elseif (
				in_array($alg, ['PS256', 'PS384', 'PS512']) &&
				!(extension_loaded('bcmath') || extension_loaded('gmp'))
			) {
				$this->logger->warning('Extension BCmath/GMP is highly recommended with JWS algorithm "{alg}".', [
					'alg' => $alg
				]);
			}
			elseif (
				in_array($alg, ['ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']) &&
				$kty != 'OKP'
			) {
				$this->logger->warning('JWE algorithm "{alg}" is recommended to use with OKP keys only, got "{kty}".', [
					'alg' => $alg,
					'kty' => $kty,
				]);
			}
			elseif ($alg === 'none') {
				$this->logger->warning('JWS algorithm "none" is NOT secure!');
			}
		}
	}

}