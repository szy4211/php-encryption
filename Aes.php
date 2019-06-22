<?php
/**
 * @description: 128 位 aes
 *
 * @date 2019-06-22
 * author zornshuai@foxmail.com
 */


class Aes
{
    protected $key;
    protected $iv;

    /**
     * Aes constructor.
     * @param $key
     * @param string $iv 16位
     */
    public function __construct($key, $iv = '0000000000000000')
    {
        $this->key = $key;
        $this->iv  = $iv;
    }

    /**
     * @description: AES加密
     *
     * @param string $str
     * @return string
     * @date 2019-06-22
     */
    public function encrypt($str)
    {
        return base64_encode(openssl_encrypt($str,
            'AES-128-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv));
    }

    /**
     * @description: AES解密
     *
     * @param $str
     * @return string
     * @date 2019-06-22
     */
    public function decrypt($str)
    {
        return openssl_decrypt(base64_decode($str),
            'AES-128-CBC',
            $this->key,
            OPENSSL_RAW_DATA, $this->iv);
    }
}
