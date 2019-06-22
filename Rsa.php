<?php
/**
 * @description: RSA加解密
 *
 */


class Rsa
{
    private $pubKey = null;
    private $priKey = null;
    private $opensslConfigPath = ""; // apache路径下的openssl.conf文件路径

    /**
     * Rsa constructor.
     * @param string $publicKeyFile 公钥文件（验签和加密时传入）
     * @param string $privateKeyFile 私钥文件（签名和解密时传入）
     * @param string $opensslConfigPath apache路径下的openssl.conf文件路径（使用Apache版本需要传入）
     */
    public function __construct($publicKeyFile = '', $privateKeyFile = '', $opensslConfigPath = '')
    {
        $this->getPublicKey($publicKeyFile);
        $this->getPrivateKey($privateKeyFile);
        $this->opensslConfigPath = $opensslConfigPath;
    }

    /**
     * @description: 自定义错误处理
     *
     * @param string $msg
     * @throws \Exception
     * @version 1.0
     * @date 2019/4/17
     */
    private function error($msg)
    {
        throw new \Exception('RSA Error:' . $msg);
    }

    /**
     * @description: 签名
     *
     * @param string $data 签名材料
     * @param string $code 签名编码（base64/hex/bin）
     * @return bool|string 签名值
     * @version 1.0
     * @date 2019/4/17
     */
    public function sign($data, $code = 'base64')
    {
        $ret = false;

        if (openssl_sign($data, $ret, $this->priKey)) {
            $ret = $this->encode($ret, $code);
        }

        return $ret;
    }

    /**
     * @description: 验证签名
     *
     * @param string $data 签名材料
     * @param string $sign 签名值
     * @param string $code 签名编码（base64/hex/bin）
     * @return bool
     * @version 1.0
     * @date 2019/4/17
     */
    public function verify($data, $sign, $code = 'base64')
    {
        $ret  = false;
        $sign = $this->decode($sign, $code);
        if ($sign !== false) {
            switch (openssl_verify($data, $sign, $this->pubKey)) {
                case 1:
                    $ret = true;
                    break;
                case 0:
                case -1:
                default:
                    $ret = false;
            }
        }
        return $ret;
    }

    /**
     * @description: 加密
     *
     * @param string $data 明文
     * @param string $code 密文编码（base64/hex/bin）
     * @param int $padding 填充方式（貌似php有bug，所以目前仅支持OPENSSL_PKCS1_PADDING）
     * @return bool|string 密文
     * @throws \Exception
     * @version 1.0
     * @date 2019/4/17
     */
    public function encrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING)
    {
        $ret = false;
        if (!$this->checkPadding($padding, 'en')) $this->error('padding error');
        if (openssl_public_encrypt($data, $result, $this->pubKey, $padding)) {
            $ret = $this->encode($result, $code);
        }
        return $ret;
    }

    /**
     * @description: 解密
     *
     * @param string $data 密文
     * @param string $code 密文编码（base64/hex/bin）
     * @param int $padding 填充方式（OPENSSL_PKCS1_PADDING / OPENSSL_NO_PADDING）
     * @param bool $rev 是否翻转明文（When passing Microsoft CryptoAPI-generated RSA cyphertext, revert the bytes in the block）
     * @return bool|string 明文
     * @throws \Exception
     * @version 1.0
     * @date 2019/4/17
     */
    public function decrypt($data, $code = 'base64', $padding = OPENSSL_PKCS1_PADDING, $rev = false)
    {
        $ret  = false;
        $data = $this->decode($data, $code);
        if (!$this->checkPadding($padding, 'de')) $this->error('padding error');
        if ($data !== false) {
            if (openssl_private_decrypt($data, $result, $this->priKey, $padding)) {
                $ret = $rev ? rtrim(strrev($result), "\0") : '' . $result;
            }
        }
        return $ret;
    }

    /**
     * @description: 生产新密匙
     *
     * @version 1.0
     * @date 2019/4/17
     */
    public function buildNewKey()
    {
        $config   = [
            'private_key_bits' => 2048,
        ];
        $resource = openssl_pkey_new($config);
        openssl_pkey_export($resource, $privateKey);
        if (!$resource) {
            $config['config'] = $this->openssl_config_path;
            $resource         = openssl_pkey_new($config);
            openssl_pkey_export($resource, $privateKey, null, $config);
        }
        $detail    = openssl_pkey_get_details($resource);
        $publicKey = $detail['key'];
        echo "<pre>";
        echo "$publicKey";

        echo "$privateKey";
        echo "</pre>";
    }

    /**
     * @description: 检测填充类型
     * 加密只支持PKCS1_PADDING
     * 解密支持PKCS1_PADDING和NO_PADDING
     *
     * @param int $padding 填充模式
     * @param string $type 加密en/解密de
     * @return bool
     * @version 1.0
     * @date 2019/4/17
     */
    private function checkPadding($padding, $type)
    {
        if ($type == 'en') {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        } else {
            switch ($padding) {
                case OPENSSL_PKCS1_PADDING:
                case OPENSSL_NO_PADDING:
                    $ret = true;
                    break;
                default:
                    $ret = false;
            }
        }
        return $ret;
    }

    private function encode($data, $code)
    {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_encode('' . $data);
                break;
            case 'hex':
                $data = bin2hex($data);
                break;
            case 'bin':
            default:
        }
        return $data;
    }

    private function decode($data, $code)
    {
        switch (strtolower($code)) {
            case 'base64':
                $data = base64_decode($data);
                break;
            case 'hex':
                $data = $this->hex2bin($data);
                break;
            case 'bin':
            default:
        }
        return $data;
    }

    private function getPublicKey($file)
    {
        $keyContent = $this->readFile($file);

        if ($keyContent) {
            $this->pubKey = openssl_get_publickey($keyContent);
        }

    }

    private function getPrivateKey($file)
    {
        $keyContent = $this->readFile($file);

        if ($keyContent) {
            $this->priKey = openssl_get_privatekey($keyContent);
        }
    }

    private function readFile($file)
    {
        $ret = false;
        if (!file_exists($file)) {
            $this->error("The file {$file} is not exists");
        } else {
            $ret = file_get_contents($file);

        }
        return $ret;
    }

    private function hex2bin($hex = false)
    {
        $ret = $hex !== false && preg_match('/^[0-9a-fA-F]+$/i', $hex) ? pack("H*", $hex) : false;
        return $ret;
    }
}
