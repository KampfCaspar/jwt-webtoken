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
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\Encryption\Serializer\JWESerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use KampfCaspar\JWT\JWT;
use KampfCaspar\JWT\JWTSerializerEnum;

/**
 * JWE Creation and Consumption Frontend using web-token
 *
 * Abstraction class that either creates a JWE (encodes) from a given payload or
 * verifies and consumes (decrypts) a JWE and returns the payload.
 */
class JWECoder extends AbstractCoder
{
	/** map of official content encryption algorithm names to web-token class names
	 * @see self::addContentEncryptionAlgorithms()
	 */
	protected const ALGORITHM_MAP_ENCRYPTION = [
		'A128CBC-HS256'      => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256',
		'A192CBC-HS384'      => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384',
		'A256CBC-HS512'      => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512',
		'A128GCM'            => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM',
		'A192GCM'            => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM',
		'A256GCM'            => 'Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM',
	];

	/** map of official key encryption algorithm names to web-token class names
	 * @see self::addKeyEncryptionAlgorithms()
	 */
	protected const ALGORITHM_MAP_KEYENCRYPTION = [
		'A128GCMKW'          => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW',
		'A192GCMKW'          => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW',
		'A256GCMKW'          => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW',
		'A128KW'             => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW',
		'A192KW'             => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW',
		'A256KW'             => 'Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW',
		'dir'                => 'Jose\Component\Encryption\Algorithm\KeyEncryption\Dir',
		'ECDH-ES+A128KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW',
		'ECDH-ES+A192KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW',
		'ECDH-ES+A256KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW',
		'ECDH-SS+A128KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW',
		'ECDH-SS+A192KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA192KW',
		'ECDH-SS+A256KW'     => 'Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA256KW',
		'PBES2-HS256+A128KW' => 'Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW',
		'PBES2-HS384+A192KW' => 'Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW',
		'PBES2-HS512+A256KW' => 'Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW',
		'RSA1_5'             => 'Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15',
		'RSA-OAEP'           => 'Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP',
		'RSA-OAEP-256'       => 'Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256',
	];

	/** all content encryption algorithms added
	 * @see self::addContentEncryptionAlgorithms()
	 * @var array<ContentEncryptionAlgorithm>
	 */
	protected array $contentAlgorithms = [];

	/** all key encryption algorithms added
	 * @see self::addKeyEncryptionAlgorithms()
	 * @var array<KeyEncryptionAlgorithm>
	 */
	protected array $keyAlgorithms = [];

	/** all serializers added for decoding
	 * @see self::decode()
	 * @var array<JWESerializer>
	 */
	protected array $serializers = [];

	protected JWEBuilder $jweBuilder;

	protected JWELoader $jweLoader;

	/**
	 * add one or many content encryption algorithms to support
	 *
	 * @param string|iterable<string> $algorithms
	 *
	 * @throws \InvalidArgumentException  if an algorithm cannot be found
	 */
	public function addContentEncryptionAlgorithms(string|Iterable $algorithms) : static
	{
		array_push($this->contentAlgorithms, ...$this->createAlgorithms(static::ALGORITHM_MAP_ENCRYPTION, $algorithms));
		unset($this->jweLoader);  // loader and builder consume the algorithms
		unset($this->jweBuilder);
		return $this;
	}

	/**
	 * add one or many key encryption algorithms to support
	 *
	 * @param string|iterable<string> $algorithms
	 *
	 * @throws \InvalidArgumentException  if an algorithm cannot be found
	 */
	public function addKeyEncryptionAlgorithms(string|Iterable $algorithms) : static
	{
		array_push($this->keyAlgorithms, ...$this->createAlgorithms(static::ALGORITHM_MAP_KEYENCRYPTION, $algorithms));
		unset($this->jweLoader);  // loader and builder consume the algorithms
		unset($this->jweBuilder);
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
		unset($this->jweLoader); // uses the collected serializers
		return $this;
	}

	/**
	 * create a SerializerManager with the collected serializers for decoding
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _createSerializerManager(): JWESerializerManager
	{
		if (!count($this->serializers)) {
			$this->addSerializer($this->defaultSerializer);
		}
		return new JWESerializerManager($this->serializers);
	}

	/**
	 * get (and create) a JWEBuilder
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _getJWEBuilder() : JWEBuilder
	{
		if (!isset($this->jweBuilder)) {
			$this->jweBuilder = new JWEBuilder(
				new AlgorithmManager($this->keyAlgorithms),
				new AlgorithmManager($this->contentAlgorithms),
				new CompressionMethodManager([new Deflate()])
			);
		}
		return $this->jweBuilder;
	}

	/**
	 * get (and create) a JWELoader
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _getJWELoader() : JWELoader
	{
		if (!isset($this->jwsLoader)) {
			$manager = new AlgorithmManager($this->keyAlgorithms);
			$this->jweLoader = new JWELoader(
				$this->_createSerializerManager(),
				new JWEDecrypter(
					$manager,
					new AlgorithmManager($this->contentAlgorithms),
					new CompressionMethodManager([new Deflate()]),
				),
				new HeaderCheckerManager(
					[
						new AlgorithmChecker($manager->list())
					],
					[
						new JWETokenSupport()
					])
			);
		}
		return $this->jweLoader;
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

		$recipients = [];
		foreach ($keys as $key) {
			if (!$this->canKeyUsage($key, 'encrypt')) {
				continue;
			}
			$foundAlg = false;
			foreach ($this->keyAlgorithms as $alg) {
				if ($this->canKeyAlgorithm($key, $alg)) {
					$foundAlg = true;
					break;
				}
			}
			if (!$foundAlg) {
				continue;
			}
			// @phpstan-ignore-next-line as $alg MUST be defined
			$recipients[] = [$key, $alg->name()];
			// @phpstan-ignore-next-line as $alg MUST be defined
			$this->logAlgorithmKeyCheck($alg, $key);

			if (!$this->encodeToMany) {
				break;
			}
		}

		if (!count($recipients)) {
			throw new \DomainException('no compatible key and algorithm found');
		}

		$builder = $this->_getJWEBuilder()
			->create()
			->withPayload($payload_binary);
		if (count($recipients) == 1) {
			$builder = $builder
				->withSharedProtectedHeader([
					'enc' => $this->contentAlgorithms[0]->name(),
					'zip' => 'DEF',
					'alg' => $recipients[0][1]
				] + $header + $header_source)
				->addRecipient($recipients[0][0]);
		}
		else {
			$builder = $builder
				->withSharedProtectedHeader([
					'enc' => $this->contentAlgorithms[0]->name(),
					'zip' => 'DEF',
				] + $header + $header_source);
			foreach ($recipients as $recipient) {
				$builder = $builder->addRecipient($recipient[0], ['alg' => $recipient[1]]);
			}
		}
		$jwe = $builder->build();

		$serializer = $serializer ?? ($this->encodeToMany ? JWTSerializerEnum::JSON : $this->defaultSerializer);
		if (!isset($this->serializers[$serializer->name])) {
			$this->addSerializer($serializer);
		}
		return $this->serializers[$serializer->name]->serialize($jwe);
	}

	/**
	 * decode and return JWE
	 *
	 * @internal  also used in {@see NestedCoder}
	 */
	public function _decodeObject(string $token): JWE
	{
		try {
			$jwe = $this->_getJWELoader()
				->loadAndDecryptWithKeySet($token, new JWKSet($this->decodeKeys), $recipient);;
		}
		catch (\Throwable $e) {
			throw new \InvalidArgumentException('invalid JWE given', $e->getCode(), $e);
		}
		return $jwe;
	}

	/**
	 * @inheritdoc
	 */
	public function decodeBinary(string $token): array
	{

		$jwe = $this->_decodeObject($token);
		return [
			$jwe->getPayload() ?? '',
			$jwe->getRecipient(0)->getHeader() + $jwe->getSharedProtectedHeader()
		];
	}

}