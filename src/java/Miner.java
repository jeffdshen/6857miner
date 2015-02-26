import com.amd.aparapi.Device;
import com.amd.aparapi.OpenCLDevice;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.PropertyConfigurator;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class Miner {
    public static String minerID = "32"; // default
    public static boolean nextMode = false;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        PropertyConfigurator.configure(Miner.class.getResource("/config/log4j.properties"));

        if (args.length >= 1) {
            minerID = args[0];
            System.out.println("alt id : " + minerID);
        }


        // use this chain for texting purposes
        Miner miner = new Miner(
            "32",
            BaseEncoding.base16().lowerCase().decode("0000006ad92f7cd7a0bc20523d3a9252a8d49accdb24ce084128d8fe5a6dc101"),
            132
        );

        if (args.length >= 3) {
            miner = new Miner(
                minerID, BaseEncoding.base16().lowerCase().decode(args[1]), Integer.parseInt(args[2]) + 1
            );
            nextMode = true;
        }

        miner = pollHead(miner);

        while (true) {
            Miner next = miner.mine();
            if (next == null) {
                miner = pollHead(miner);
            } else {
                miner = next;
            }
        }
    }

    public static Miner pollHead(Miner miner) throws IOException, NoSuchAlgorithmException {
        //instantiates httpclient to make request
        DefaultHttpClient httpclient = new DefaultHttpClient();

        String hashString = BaseEncoding.base16().lowerCase().encode(miner.hash);
        //url with the post data
        String url = nextMode ? "http://6857coin.csail.mit.edu/next/" + hashString : "http://6857coin.csail.mit.edu/head";
        HttpGet httpost = new HttpGet(url);

        //convert parameters into JSON object
        //Handles what is returned from the page
        HttpResponse response = httpclient.execute(httpost);
        String s = EntityUtils.toString(response.getEntity());
        if (s.contains("no next block")) {
            return miner;
        }
        
        // create an ObjectMapper instance.
        ObjectMapper mapper = new ObjectMapper();
        // use the ObjectMapper to read the json string and create a tree
        JsonNode node = mapper.readTree(s);
        String hash = node.findValue("PrevHash").getTextValue();
        int length = node.findValue("Length").getIntValue();
        long nonce = node.findValue("Nonce").getLongValue();
        String contents = node.findValue("Contents").getTextValue();

        byte[] sha = sha256(hash, contents, nonce, length);
        System.out.println("hash : " + BaseEncoding.base16().lowerCase().encode(sha) + ", length: " + length);

        return new Miner(minerID, sha, length + 1);
    }

    private byte[] hash;
    private int length;
    private byte[] contentsBytes;
    private String contents;

    public Miner(String contents, byte[] hash, int length) {
        this.hash = hash;
        this.length = length;
        this.contents = contents;
        contentsBytes = contents.getBytes();
    }

    public Miner mine() throws NoSuchAlgorithmException, IOException, InterruptedException {
        int proc = Runtime.getRuntime().availableProcessors();
        System.out.println("procs: " + proc);
        int threads = 16384;
        long mod = threads;

        byte[] lengthBytes = Ints.toByteArray(length);
        byte[] block = new byte[hash.length + contentsBytes.length + 8 + lengthBytes.length];
        System.arraycopy(hash, 0, block, 0, hash.length);
        System.arraycopy(contentsBytes, 0, block, hash.length, contentsBytes.length);
        System.arraycopy(lengthBytes, 0, block, hash.length + contentsBytes.length + 8, lengthBytes.length);

        System.out.println(block.length + "," + contentsBytes.length);

        long time = System.currentTimeMillis();
        Device best = Device.best();
        OpenCLDevice.DeviceSelector selector = new OpenCLDevice.DeviceSelector() {
            @Override

            public OpenCLDevice select(OpenCLDevice openCLDevice) {
                System.out.println(openCLDevice.getPlatform().getVendor());
                System.out.println(openCLDevice.getPlatform().getName());
                System.out.println(openCLDevice.getPlatform().getVersion());
                System.out.println(openCLDevice.getPlatform().toString());
                if (openCLDevice.getType() == Device.TYPE.GPU && openCLDevice.getPlatform().getVendor().toUpperCase().contains("NVIDIA")) {
                    return openCLDevice;
                }
                return null;
            }
        };

        System.out.println(best);

        Device nvidia = OpenCLDevice.select(selector);

        if (nvidia != null) {
            best = nvidia;
        } else if (best.getType() != Device.TYPE.GPU) {
            best = Device.firstGPU();
        }

        System.out.println(best);
        Random r = new Random();
        long lastCount = 0;
        for (long i = 0; true; i++) {
            System.out.println("finished: " + i * threads * 1_000_000);
            long nonceBlock = Math.abs(r.nextLong());
            System.out.println("current nonceBlock: " + nonceBlock);
            GpuSha256 kernel = new GpuSha256(block, nonceBlock, mod, length);
            kernel.execute(best.createRange(threads));
            System.out.println(kernel.getExecutionMode());
            if (kernel.solved[0]) {
                byte[] nonce = Longs.toByteArray(kernel.nonce[0]);
                byte[] next = kernel.target;
                System.out.println("FOUND HASH: " + BaseEncoding.base16().lowerCase().encode(next));
                post(BaseEncoding.base16().lowerCase().encode(hash), contents, kernel.nonce[0], length);
                return null;
            }

//            if (count == 0) {
//                Thread.sleep(20000);
//                count = 20;
//            }
//            count--;
//            do poll
            long cur = System.currentTimeMillis();
            if (cur - time >= 30000) {
                long hps = (i - lastCount) * threads * 1_000_000 * 1000 / (cur - time);
                lastCount = i;
                System.out.println("HASHES PER SECOND: " + hps);
                time = cur;
                Miner miner = pollHead(this);
                if (miner.length != length) {
                    return miner;
                }
            }
        }
    }

    public static byte[] sha256(String hashString, String contents, long nonce, int length) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] contentsBytes = contents.getBytes();
        byte[] hash = BaseEncoding.base16().lowerCase().decode(hashString);
        byte[] lengthBytes = Ints.toByteArray(length);
        byte[] nonceBytes = Longs.toByteArray(nonce);

        byte[] block = new byte[hash.length + contentsBytes.length + 8 + lengthBytes.length];
        System.arraycopy(hash, 0, block, 0, hash.length);
        System.arraycopy(contentsBytes, 0, block, hash.length, contentsBytes.length);
        System.arraycopy(lengthBytes, 0, block, hash.length + contentsBytes.length + 8, lengthBytes.length);
        System.arraycopy(nonceBytes, 0, block, hash.length + contentsBytes.length, 8);
        return digest.digest(block);
    }

    public static void post(String hash, String contents, long nonce, int length) throws IOException {
        //instantiates httpclient to make request
        DefaultHttpClient httpclient = new DefaultHttpClient();

        //url with the post data
        HttpPost httpost = new HttpPost("http://6857coin.csail.mit.edu/add");

        //convert parameters into JSON object
        String fmt = "{\n" +
            "  \"PrevHash\": \"%s\",\n" +
            "  \"Contents\": \"%s\",\n" +
            "  \"Nonce\": %d,\n" +
            "  \"Length\": %d\n" +
            "}";

        System.out.println("FOUND: " + String.format(fmt, hash, contents, nonce, length));
        //passes the results to a string builder/entity
        StringEntity se = new StringEntity(String.format(fmt, hash, contents, nonce, length));

        //sets the post request as the resulting string
        httpost.setEntity(se);
        //sets a request header so the page receving the request
        //will know what to do with it
        httpost.setHeader("Accept", "application/json");
        httpost.setHeader("Content-type", "application/json");

        //Handles what is returned from the page
        ResponseHandler responseHandler = new BasicResponseHandler();
        System.out.println(httpclient.execute(httpost, responseHandler));
    }
}
