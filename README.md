# Google Authenticator

`是谷歌推出的一款动态口令工具，解决大家的google账户遭到恶意攻击的问题；许多安全性比较高的网站都会采用这种工具来验证登录或者交易；这个动态口令就是Google身份验证器每隔30s会动态生成一个6位数的数字。它的作用是：对你的账号进行“二步验证”保护，或者说做一个双重身份验证，来达到提升安全级别的目的。`

通过 一致算法保持手机端和服务端相同，并每30秒改变认证码。

### 方法说明
    GetSecret() ：获取秘钥（32位字符串
    GetCode() ：获取动态码
    GetQrcode() ：获取动态码二维码内容
    GetQrcodeUrl() ：获取动态码二维码图片地址
    VerifyCode() ：验证动态码

otp是什么知道么？ 是一次性密码，简单的说，totp是基于时间的，htop是基于次数的。

秘钥生成原理（基于时间）

    1、时间戳，精确到微秒，除以1000，除以30（动态6位数字每30秒变化一次）
    2、对时间戳余数 hmac_sha1 编码
    3、然后 base32 encode 标准编码
    4、输出大写字符串，即秘钥

动态6位数字验证：
Google Authenticator会基于密钥和时间计算一个HMAC-SHA1的hash值，这个hash是160 bit的，然后将这个hash值随机取连续的4个字节生成32位整数，最后将整数取31位，再取模得到一个的整数。

这个就是Google Authenticator显示的数字。

在服务器端验证的时候，同样的方法来计算出数字，然后比较计算出来的结果和用户输入的是否一致。

代码示例：

 	func main() {
 	    fmt.Println("-----------------开启二次认证----------------------")
 	    user := "demo"
 	    secret, code := initAuth(user)
 	    fmt.Println(secret, code)

 	    fmt.Println("-----------------信息校验----------------------")
 
 	    // secret最好持久化保存在
 	    // 验证,动态码(从谷歌验证器获取或者freeotp获取)
 	    ok, err := NewGoogleAuth().VerifyCode(secret, code)
 	    if ok {
 		    fmt.Println("√")
 	    } else {
 	    	fmt.Println("X", err)
 	    }
    }
 
    // 开启二次认证
    func initAuth(user string) (secret, code string) {
 	    // 秘钥
 	    secret = NewGoogleAuth().GetSecret()
 	    fmt.Println("Secret:", secret)
 
 	    // 动态码(每隔30s会动态生成一个6位数的数字)
 	    code, err := NewGoogleAuth().GetCode(secret)
 	    fmt.Println("Code:", code, err)
 
 	    // 用户名
 	    qrCode := NewGoogleAuth().GetQrcode(user, code)
 	    fmt.Println("Qrcode", qrCode)
 
 	    // 打印二维码地址
 	    qrCodeUrl := NewGoogleAuth().GetQrcodeUrl(user, secret)
 	    fmt.Println("QrcodeUrl", qrCodeUrl)
 
 	    return
    }