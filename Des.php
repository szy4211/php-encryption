<?php
/**
 * @description: des对称加密
 *
 * @date 2019-06-21
 * author zornshuai@foxmail.com
 */

class Des
{
    protected $key;
    protected $iv;

    /**
     * Des constructor.
     * @param string $key
     * @param string $iv 8位
     */
    public function __construct($key, $iv = '00000000')
    {
        $this->key = $key;
        $this->iv  = $iv;
    }

    public function encrypt($data)
    {
        return openssl_encrypt($data, 'des-cbc', $this->key, 0, $this->iv);
    }

    public function decrypt($data)
    {
        return openssl_decrypt($data, 'des-cbc', $this->key, 0, $this->iv);
    }
}
