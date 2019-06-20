package openapi;

import com.google.gson.GsonBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.compression.CompressionCodecs;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

//import com.auth0.jwt.Algorithm;
//import com.auth0.jwt.JWTSigner;
//import com.auth0.jwt.JWT;
//import com.auth0.jwt.algorithms.Algorithm;
//import com.auth0.jwt.exceptions.JWTCreationException;
//import com.auth0.jwt.internal.org.apache.commons.lang3.StringUtils;


/**
 * @author xingguoqing
 * @date 2017/12/4 下午7:25
 */
public class InsertWithArray {

    public static void main(String[] args) {
        try {
            new InsertWithArray().callInvoiceApply();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 调用接口开票
     * @throws Exception
     */
    public void callInvoiceApply() throws Exception {
        String url = "https://yesfp.yonyoucloud.com/invoiceclient-web/api/invoiceApply/insertWithArray?"
                + "appid=commontesterCA";
        HttpClient httpClient = HttpClients.custom().build();
        HttpPost httpPost = new HttpPost(url);
        // 构造POST表单Map
        Map<String, String> paramsMap = buildPostParam();
        System.out.println(paramsMap);
        // 签名
        String sign = this.sign(paramsMap);
        System.out.println(sign);
        httpPost.addHeader("sign", sign);
        // 转换POST表单参数
        List<NameValuePair> list = new ArrayList<NameValuePair>();
        Iterator<Entry<String, String>> iterator = paramsMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Entry<String, String> elem = iterator.next();
            list.add(new BasicNameValuePair(elem.getKey(), elem.getValue()));
        }
        if (list.size() > 0) {
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(list, "UTF-8");
            httpPost.setEntity(entity);
        }
        // 发送http post请求，并得到响应结果
        HttpResponse response = httpClient.execute(httpPost);
        String result;
        if (response != null) {
            HttpEntity resEntity = response.getEntity();
            if (resEntity != null) {
                result = EntityUtils.toString(resEntity, "UTF-8");
                System.out.println(result);
            }
        }
    }

//    /**
//     * 签名
//     *
//     * @param paramsMap 表单参数
//     * @return 签名值
//     * @throws Exception
//     */
//    private String sign(Map<String, String> paramsMap) throws Exception {
//
//        // 读取CA证书与PEM格式证书需要根据实际证书使用情况而定,目前这两种都支持
//        PrivateKey privateKey = loadPrivateKeyOfCA();
////        PrivateKey privateKey = loadPrivateKeyOfPem();
//
//        Map<String, Object> claims =
//                JwtParamBuilder.build().setSubject("tester").setIssuer("einvoice").setAudience("einvoice")
//                        .addJwtId().addIssuedAt().setExpirySeconds(300).setNotBeforeSeconds(300).getClaims();
//
//        // 需要将表单参数requestdatas的数据进行md5加密，然后放到签名数据的requestdatas中。
//        // 此签名数据必须存在，否则在验证签名时会不通过。
//        String value = paramsMap.get("requestdatas");
//        claims.put("requestdatas", getMD5(value));
//
//        // 使用jdk1.6版本时，删除下面代码的中.compressWith(CompressionCodecs.DEFLATE)
//        String compactJws = Jwts.builder().signWith(SignatureAlgorithm.RS512, privateKey)
//                .setClaims(claims).compressWith(CompressionCodecs.DEFLATE).compact();
//
//        return compactJws;
//    }

    /**
     * 签名
     *
     * @param paramsMap 表单参数
     * @return 签名值
     * @throws Exception
     */
    private String sign(Map<String, String> paramsMap) throws Exception {

//        // 读取CA证书与PEM格式证书需要根据实际证书使用情况而定,目前这两种都支持
//        RSAPrivateKey privateKey = loadPrivateKeyOfCA();
//        Map<String, Object> claims = new HashMap<String, Object>();
//
//        String value = paramsMap.get("requestdatas");
//
//        System.out.println(value);
//        System.out.println(getMD5(value));
//        if (StringUtils.isNotEmpty(value)) {
//            claims.put("requestdatas", getMD5(value));
//        }
//
//        claims.put("iss", "u8c");
//        claims.put("sub", "u8c");
//        claims.put("aud", "einvoice");
//
//        JWTSigner signer = new JWTSigner(privateKey);
//        String token =
//                signer.sign(claims, new JWTSigner.Options().setExpirySeconds(3600)
//                        .setNotValidBeforeLeeway(3600).setIssuedAt(true).setJwtId(true)
//                        .setAlgorithm(Algorithm.RS256));
//        System.out.println(token);
//        return token;
//        Map<String, Object> claims =
//                JwtParamBuilder.build().setSubject("tester").setIssuer("einvoice").setAudience("einvoice")
//                        .addJwtId().addIssuedAt().setExpirySeconds(300).setNotBeforeSeconds(300).getClaims();
//        String token;
//        try {
//            Algorithm algorithm = Algorithm.RSA512(null, privateKey);
//            token = JWT.create()
//                    .withClaim("requestdatas",getMD5(paramsMap.get("requestdatas")))
//                    .withHeader(claims)
//                    .sign(algorithm);
//        } catch (JWTCreationException exception){
//            //Invalid Signing configuration / Couldn't convert Claims.
//            return null;
//        }
//
//        return token;


        PrivateKey privateKey = loadPrivateKeyOfCA();

        Map<String, Object> claims =
                JwtParamBuilder.build().setSubject("tester").setIssuer("einvoice").setAudience("einvoice")
                        .addJwtId().addIssuedAt().setExpirySeconds(300).setNotBeforeSeconds(300).getClaims();

        // 需要将表单参数requestdatas的数据进行md5加密，然后放到签名数据的requestdatas中。
        // 此签名数据必须存在，否则在验证签名时会不通过。
        String value = paramsMap.get("requestdatas");
        claims.put("requestdatas", getMD5(value));

        // 使用jdk1.6版本时，删除下面代码的中.compressWith(CompressionCodecs.DEFLATE)
        String compactJws = Jwts.builder().signWith(SignatureAlgorithm.RS512, privateKey)
                .setClaims(claims).compressWith(CompressionCodecs.DEFLATE).compact();

        return compactJws;
    }
//    HttpClient httpClient = createSSLClientDefault();    //忽略https证书

    private static CloseableHttpClient createSSLClientDefault() {
        try {
            SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                @Override
                public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                    return true;
                }

//                //信任所有
//                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
//                    return true;
//                }
            }).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    return true;
                }
            });

            ////SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
            return HttpClients.custom().setSSLSocketFactory(sslsf).build();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return HttpClients.createDefault();
    }

    /**
     * 计算MD5
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
//    private String getMD5(String str) throws UnsupportedEncodingException, NoSuchAlgorithmException {
//        byte[] buf = null;
//        buf = str.getBytes("utf-8");
//        MessageDigest md5 = null;
//        md5 = MessageDigest.getInstance("MD5");
//        md5.update(buf);
//        byte[] tmp = md5.digest();
//        StringBuilder sb = new StringBuilder();
//        for (byte b : tmp) {
//            sb.append(String.format("%02x", b & 0xff));
//        }
//        return sb.toString();
//    }
    private static String getMD5(String str) throws UnsupportedEncodingException,
            NoSuchAlgorithmException {
        byte[] buf = null;
        buf = str.getBytes("utf-8");
        MessageDigest md5 = null;
        md5 = MessageDigest.getInstance("MD5");
        md5.update(buf);
        byte[] tmp = md5.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : tmp) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }


    /**
     * 读取证书私钥
     *
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    protected RSAPrivateKey loadPrivateKeyOfCA() throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        String keypath = "src/main/resources/certificate/pro22.pfx";
        FileInputStream in = new FileInputStream(keypath);
        KeyStore ks = KeyStore.getInstance("pkcs12");
        String pwd = "password";
        ks.load(in, pwd.toCharArray());
        String alias = ks.aliases().nextElement();
        RSAPrivateKey caprk = (RSAPrivateKey) ks.getKey(alias, pwd.toCharArray());
        return caprk;
    }


    /**
     * post表单数据
     *
     * @return
     */
    private Map<String, String> buildPostParam() {
        Map<String, String> paramsMap = new HashMap<String, String>();
        paramsMap.put("requestdatas", this.buildRequestDatas());
//        paramsMap.put("url", this.buildRequesturl());
//        paramsMap.put("email", this.buildEmailConfigs());
//        paramsMap.put("sms", this.buildSmsConfigs());
        paramsMap.put("url", this.buildUrlConfigs());
//        paramsMap.put("autoAudit", "false");

        return paramsMap;
    }

    private String buildRequesturl() {
        List<Object> datas = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("FPQQLSH", buildFpqqlsh());
        data.put("url", "http://117.5.26.2/invoice");
        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(datas);
    }

    /**
     * url回掉配置
     *
     * @return
     */
    private String buildUrlConfigs() {
        List<Object> datas = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("fpqqlsh", buildFpqqlsh());
        data.put("url", "http://117.12.12.3:7787/EinvoiceRESTService/CallBackEInvoices/");
        datas.add(data);

        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(datas);
    }

    /**
     * 构造短信发送信息
     *
     * @return
     */
    private String buildSmsConfigs() {
        List<Object> datas = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
//        data.put("fpqqlsh", buildFpqqlsh());
        data.put("address", "15611500957");
        datas.add(data);

        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(datas);
    }

    /**
     * 构造email发送信息
     *
     * @return
     */
    private String buildEmailConfigs() {
        List<Object> datas = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("fpqqlsh", buildFpqqlsh());
        data.put("address", "xinggq7@yonyou.com");
        datas.add(data);

        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(datas);
    }

    /**
     * 构造requestdatas
     *
     * @return
     */
    private String buildRequestDatas() {
        List<Object> datas = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("FPQQLSH", buildFpqqlsh());
        data.put("XSF_NSRSBH", "201609140000001");
//        data.put("FPLX", "9");
        data.put("GMF_MC", "123");
//        data.put("GMF_DZDH", "撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的撒打算打算的");
//        data.put("ORGCODE", "20160914001");
//        data.put("GMF_NSRSBH", "%^&*&^%$#");
//        data.put("SGBZ", "2");
//        data.put("FHR", "玩儿第七位额");
//        data.put("GMF_MC", "梁健雄!@#$#%^$%容茵\n");
        data.put("JSHJ", 1395.00);
////        19999999.00
//        data.put("items", buildItems());
//        data.put("BMB_BBH", "13.0");
//        data.put("BZ", "");
//        data.put("FHR", "杨明");
//        data.put("FPLX", "1");
//        data.put("FPQQLSH", "V1804240639A");
//        data.put("GMF_DZDH", "长沙市雨花区车站南路550号18684750078");
//        data.put("GMF_MC", "长沙雨花周蓉诊所");
//        data.put("GMF_MC", "长沙雨花周蓉诊所");
//        data.put("GMF_NSRSBH", "无");
//        data.put("GMF_YHZH", "");
//        data.put("HJJE", "");
//        data.put("HJSE", "");
//        data.put("JSHJ", "1395.00");
//        data.put("KPR", "陈佳博");
//        data.put("LYID", "");
//        data.put("ORGCODE", "");
//        data.put("SKR", "彭立青");
//        data.put("WXAPPID", "");
//        data.put("WXORDERID", "");
//        data.put("XSF_DZDH", "长沙市天心区新岭路78号 0731-81876288");
//        data.put("XSF_MC", "湖南同安医药有限公司");
//        data.put("XSF_NSRSBH", "91430100685027803C");
//        data.put("XSF_YHZH", "交通银行长沙府中支行  431621000018160045123");
        data.put("items", buildItems());
        datas.add(data);
        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(datas);
    }

    /**
     * 构造request发票明细
     *
     * @return
     */
    private List<Object> buildItems() {
        List<Object> items = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
//        data.put("XMMC", "ss");
//        data.put("XMJSHJ", 132400.00);
//        data.put("SL", 0.11);
//        data.put("SPBM", "1070302100000000000");
//        data.put("DW", "瓶 ");
//        data.put("FPHXZ", "0 ");
//        data.put("GGXH", "500ml:4.5g");
//        data.put("HH", "");
//        data.put("KCE", "");
//        data.put("LSLBS", "");
//        data.put("SE", "");
//        data.put("SL", "0.17");
//        data.put("SPBM", "107030204");
//        data.put("XMDJ", "");
//        data.put("XMJE", "");
        data.put("XMJSHJ", "1395.00");
        data.put("XMMC", "住宅物业管理费");
//        data.put("XMSL", "");
//        data.put("YHZCBS", "0");
//        data.put("ZKHHH", "");
//        data.put("ZXBM", "");
//        data.put("ZZSTSGL", "");

        items.add(data);

        return items;
    }


    /**
     * 获取发票请求流水号
     *
     * @return 发票请求流水号
     */
    private String buildFpqqlsh() {
        return "1k4291i05h2080000sKs";
    }



}
