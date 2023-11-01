<?php

namespace KampfCaspar\Test\JWT\WebToken;

use PHPUnit\Framework\TestCase;

abstract class AbstractCoderCase extends TestCase
{
	protected const KEYS = [
		'EC' => [
			'kty' => 'EC',
			'crv' => 'P-256',
			'd' => 'zWM7QFfjXkcRZu_nj_RZbJ4C7I2Qx0kRMhmWNUcGgZk',
			'x' => '_a6MJbbaJYs-X9sqckq2TDeQ8Y5JN4Xv2SsvuDJWrCE',
			'y' => '1FTHqtHjG58gPL2BXzqp86f-U1WFOHd0iTWaoGnX7fk',
		],
		'oct' => [
			'kty' => 'oct',
			'k' => 'AlCEmNDLJEr1UL2EY7sKbw'
		],
		'RSA' => [
			'kty' => 'RSA',
			'n' => 'zuq-U5HjGxIshB_NoqSPqLl-3j3MwudIo2cgpzZWrUkL5oHWQ05zmXJ3tJ7Y1Am16cJsAzdtwthrbWt5EsH28w',
			'e' => 'AQAB',
			'd' => 'Nu7dXqRxjcNSbDVhS5eyyBGPHAN-NBRhFXiQk7P6aQBrz82Wzb1ELJwbJkF4HwPYBGuSuIQN4jPvfR73a1OF-Q',
			'p' => '_Y-fAh5u4zyWAWKgoEqUCw9PsSkkox309MAD8HA71O8',
			'q' => '0OhDnqueT5TA7A1jwMqcijrIjTWUdKeZNYo3wEbnZj0',
			'dp' => 'XHjtd5tbu3nUBytOA0dPmHz8BlNH7kk1lbEVfrGf0Hc',
			'dq' => 'cRmeKlQtlFYrkGC7ZdALqgajN1gPtIxcNRFMl6uLcd0',
			'qi' => 'koSFhFuQcoOv5i8z55UibWjm-kgcOvCL2RTDdI1CQR8',
		],
		'none' => [
			'kty' => 'none',
			'alg' => 'none',
			'use' => 'sig',
		]
	];

	protected const PAYLOAD = [
		'alpha' => 'beta',
		'gamma' => 0,
		'delta' => [
			'alpha', 'beta', 'gamma'
		],
	];

}
