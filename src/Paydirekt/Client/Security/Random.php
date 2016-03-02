<?php

namespace Paydirekt\Client\Security;

/**
 * Wrapper class to generate a string of pseudo-random bytes with desired length.
 */
final class Random
{
    /**
     * Private constructor.
     * <p>
     * This class provides static functions only.
     */
    private function __construct() {}

    /**
     * Creates a pseudo-random string of bytes.
     * <p>
     * openssl_random_pseudo_bytes() did not always return a cryptographically strong
     * result. See bug report https://bugs.php.net/bug.php?id=70014 for further
     * details. A fix is provided as of PHP 5.4.44, 5.5.28 and 5.6.12.
     *
     * @param int $length The length of the desired string of bytes. Must be a positive integer.
     *
     * @return string The string of bytes.
     */
    public static function createRandomPseudoBytes($length)
    {
        if ($length <= 0) {
            throw new \InvalidArgumentException("length is not a positive integer");
        }

        if (version_compare(PHP_VERSION, "7.0.0", ">=") && function_exists("random_bytes")) {
            $bytes = random_bytes($length);
            return $bytes;
        }

        if (!(version_compare(PHP_VERSION, "5.4.44", ">=") && version_compare(PHP_VERSION, "5.5.0", "<")) &&
            !(version_compare(PHP_VERSION, "5.5.28", ">=") && version_compare(PHP_VERSION, "5.6.0", "<")) &&
            !(version_compare(PHP_VERSION, "5.6.12", ">="))) {
            throw new \RuntimeException("Insecure OpenSSL extension found. Please consider to update the PHP version");
        }

        if (!function_exists("openssl_random_pseudo_bytes")) {
            throw new \RuntimeException("OpenSSL extension not loaded");
        }

        $bytes = openssl_random_pseudo_bytes($length, $strong);

        if (!$strong) {
            throw new \RuntimeException("Unable to generate a cryptographically strong result");
        }

        return $bytes;
    }
}
