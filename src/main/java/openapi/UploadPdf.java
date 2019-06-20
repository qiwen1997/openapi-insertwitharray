package openapi;

import com.google.gson.GsonBuilder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.compression.CompressionCodecs;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * @author xingguoqing
 * @date 2018/8/7 下午4:37
 */
public class UploadPdf {


    private static String APPID = "commontesterCA";
    private static String DOMAIN = "http://127.0.0.1:9900";
    private static String URL = DOMAIN + "/input-tax/api/estateDeduction/upload?appid=" + APPID;
    private static String KEYPATH = "src/main/resources/certificate/pro22.pfx";
    private static String PASSWORD = "password";

    public static void main(String[] args) {
        try {
            new UploadPdf().uploadPdf();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static CloseableHttpClient createSSLClientDefault() {
        try {
            //忽略掉对服务端证书的校验
            SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                @Override
                public boolean isTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                    return true;
                }
            }).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    return true;
                }
            });
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

    public void uploadPdf() throws Exception {
        HttpClient httpClient = createSSLClientDefault();    //信任所有https证书
        HttpPost httpPost = new HttpPost(URL);
        // 构造POST请求体
        String body = this.buildRequestDatasQR();
        // 签名
        String sign = this.sign("");
        httpPost.addHeader("sign", sign);
        httpPost.addHeader(HTTP.CONTENT_TYPE, "application/json");
        StringEntity se = new StringEntity(body.toString(), "UTF-8");
        se.setContentType("text/json");
        se.setContentEncoding(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
        httpPost.setEntity(se);
        // 发送http post请求，并得到响应结果
        HttpResponse response = httpClient.execute(httpPost);
        String result = "";
        if (response != null) {
            HttpEntity resEntity = response.getEntity();
            if (resEntity != null) {
                result = EntityUtils.toString(resEntity, "UTF-8");
                System.out.println(result);
            }
        }
    }


    /**
     * 签名
     *
     * @param paramsMap 表单参数
     * @return 签名值
     * @throws Exception
     */
    private String sign(String paramsMap) throws Exception {

        // 读取CA证书与PEM格式证书需要根据实际证书使用情况而定,目前这两种都支持
        PrivateKey privateKey = loadPrivateKeyOfCA();
        // PrivateKey privateKey = loadPrivateKeyOfPem();

        Map<String, Object> claims =
                JwtParamBuilder.build().setSubject("tester").setIssuer("einvoice").setAudience("einvoice")
                        .addJwtId().addIssuedAt().getClaims();

        // 需要将表单参数requestdatas的数据进行md5加密，然后放到签名数据的requestdatas中。
        // 此签名数据必须存在，否则在验证签名时会不通过。
        System.out.println(getMD5(paramsMap));
        claims.put("requestdatas", getMD5(paramsMap));
        // 使用jdk1.6版本时，删除下面代码的中.compressWith(CompressionCodecs.DEFLATE)
        String compactJws = Jwts.builder().signWith(SignatureAlgorithm.RS512, privateKey)
                .setClaims(claims).compressWith(CompressionCodecs.DEFLATE).compact();

        return compactJws;
    }


    /**
     * 计算MD5
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    private String getMD5(String str) throws UnsupportedEncodingException, NoSuchAlgorithmException {
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
    protected PrivateKey loadPrivateKeyOfCA() throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        FileInputStream in = new FileInputStream(KEYPATH);
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(in, PASSWORD.toCharArray());
        String alias = ks.aliases().nextElement();
        PrivateKey caprk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        return caprk;
    }

    /**
     * 读取PEM编码格式
     *
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    protected PrivateKey loadPrivateKeyOfPem()
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemReader reader = new PemReader(new FileReader("D:\\CA\\keystore\\红桔.private"));
        byte[] privateKeyBytes = reader.readPemObject().getContent();
        reader.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
        return privateKey;
    }


    /**
     * 构造requestdatas
     *
     * @return
     */
    private String buildRequestDatasQR() {
        Map<String, Object> data = new HashMap<>();
        data.put("usercode","123@163.com");
        data.put("orgcode","yonyou00");
        List<Map<String, Object>> item = new ArrayList<>();

        Map<String, Object> a = new HashMap<>();
        a.put("fileName","a.pdf");
        try {
            a.put("content", FileUitl.encodeBase64File("C:/Users/mi/Desktop/qw.pdf"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        item.add(a);

        data.put("pdfFiles",item);
        GsonBuilder builder = new GsonBuilder();
        return builder.create().toJson(data);
    }

    /**
     * 获取发票请求流水号
     * 长度不超过20位，长度在1到20位的字母和数字组合，不可以重复的，不要包含window系统文件名限制的特殊字符
     *
     * @return 发票请求流水号
     */
    private String buildFpqqlsh() {
        return "1234789025622";
    }


    /**
     * 构造request发票明细
     *
     * @return
     */
    private List<Object> buildItems() {
        List<Object> items = new ArrayList<>();
        Map<String, Object> data = new HashMap<>();
        data.put("XMMC", "项目名称");
        data.put("XMJSHJ", 117);
        //税率17%需要写成0.17的格式
        data.put("SL", 0.17);
        data.put("XMSL", 1);
//        data.put("XMJSHJ", 117);
        //SPBM字段为商品税收分类编码，不同的商品会有不同的编码，不对应的话会影响报税，需要咨询下公司财务
        data.put("SPBM", "3010504020000000000");
        items.add(data);
        return items;
    }
}
