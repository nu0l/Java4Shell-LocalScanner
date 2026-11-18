import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class Smoke {
    public static void main(String[] args) throws InterruptedException {
        byte[] input = "Java4Shell local scanner smoke test".repeat(32)
                .getBytes(StandardCharsets.UTF_8);
        byte[] encoded = Base64.getEncoder().encode(input);
        for (int i = 0; i < 64; i++) {
            if (!Arrays.equals(input, Base64.getDecoder().decode(encoded))) {
                throw new AssertionError("Valid Base64 did not round-trip");
            }
        }
        System.out.println("SMOKE_READY");
        System.out.flush();
        Thread.sleep(30_000);
    }
}
