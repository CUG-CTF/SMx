import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.IntFunction;

import com.google.common.primitives.Bytes;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.util.Memoable;

public class SM2Ring {

    public static class SM2Params {
        public static SM2P256V1Curve curve = new SM2P256V1Curve();
        public static BigInteger p = curve.getQ();
        public static BigInteger q = curve.getOrder();
        public static BigInteger a = curve.getA().toBigInteger();
        public static BigInteger b = curve.getB().toBigInteger();
        public static ECPoint g = curve.createPoint(
                new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
                new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16));

    }

    public static class Signature {
        public BigInteger c;
        public BigInteger[] s;
    }

    static SecureRandom rnd = new SecureRandom();

    static byte[] sm3_digest(SM3Digest digest, Memoable state, byte[] msg) {
        digest.reset(state);
        digest.update(msg, 0, msg.length);
        byte[] res = new byte[32];
        digest.doFinal(res, 0);
        return res;
    }

    static byte[] ECPoint2Bytes(ECPoint point) {
        point = point.normalize();
        byte[] x = point.getAffineXCoord().toBigInteger().toByteArray();
        byte[] y = point.getAffineYCoord().toBigInteger().toByteArray();
        if (x.length > 32) {
            x = Arrays.copyOfRange(x, 1, 33);
        } else if (x.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(x, 0, tmp, 32 - x.length, x.length);
            x = tmp;
        }
        if (y.length > 32) {
            y = Arrays.copyOfRange(y, 1, 33);
        } else if (y.length < 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(y, 0, tmp, 32 - y.length, y.length);
            y = tmp;
        }
        byte[] res = new byte[64];
        System.arraycopy(x, 0, res, 32 - x.length, x.length);
        System.arraycopy(y, 0, res, 64 - y.length, y.length);
        return res;
    }

    static Signature sm2_ring_sign(byte[] msg, ECPoint[] pubkeys, BigInteger prikey, int pai) {
        IntFunction<Integer> wrap = x -> {
            if (x >= pubkeys.length)
                x -= pubkeys.length;
            return x;
        };
        byte[] pubkeyBytes = Bytes.concat(Arrays.stream(pubkeys).map(x -> ECPoint2Bytes(x)).toArray(byte[][]::new));
        SM3Digest digest = new SM3Digest();
        digest.update(pubkeyBytes, 0, pubkeyBytes.length);
        digest.update(msg, 0, msg.length);
        var digest_init_state = digest.copy();
        BigInteger[] s = new BigInteger[pubkeys.length];
        byte[][] c = new byte[pubkeys.length][32];
        var kpai = random_ZqM();
        c[wrap.apply(pai + 1)] = sm3_digest(digest, digest_init_state, ECPoint2Bytes(SM2Params.g.multiply(kpai)));
        for (int i = 1; i < pubkeys.length; i++) {
            int j = wrap.apply(pai + i);
            s[j] = random_ZqM();
            ECPoint Z = pubkeys[j].multiply(s[j]).add(SM2Params.g.multiply(new BigInteger(c[j])));
            c[wrap.apply(j + 1)] = sm3_digest(digest, digest_init_state, ECPoint2Bytes(Z));
        }
        s[pai] = prikey.modInverse(SM2Params.q).multiply(kpai.subtract(new BigInteger(c[pai]))).mod(SM2Params.q);
        var ret = new Signature();
        ret.c = new BigInteger(c[0]);
        ret.s = s;
        return ret;
    }

    static boolean sm2_ring_verify(byte[] msg, ECPoint[] pubkeys, Signature sig) {
        if (sig.s.length != pubkeys.length)
            return false;
        if (BigInteger.ZERO.equals(sig.c) || sig.c.compareTo(SM2Params.q) >= 0)
            return false;
        for (BigInteger b : sig.s)
            if (BigInteger.ZERO.equals(b) || b.compareTo(SM2Params.q) >= 0)
                return false;

        byte[] pubkeyBytes = Bytes.concat(Arrays.stream(pubkeys).map(x -> ECPoint2Bytes(x)).toArray(byte[][]::new));
        SM3Digest digest = new SM3Digest();
        digest.update(pubkeyBytes, 0, pubkeyBytes.length);
        digest.update(msg, 0, msg.length);
        var digest_init_state = digest.copy();
        BigInteger lastc = sig.c;
        for (int i = 0; i < sig.s.length; i++) {
            ECPoint Z = pubkeys[i].multiply(sig.s[i]).add(SM2Params.g.multiply(lastc));
            lastc = new BigInteger(sm3_digest(digest, digest_init_state, ECPoint2Bytes(Z)));
        }
        return lastc.equals(sig.c);
    }

    static BigInteger random_ZqM() {

        var len = SM2Params.q.bitLength();
        BigInteger ret;
        do {
            ret = new BigInteger(len, rnd);
        } while (BigInteger.ZERO.equals(ret) || ret.compareTo(SM2Params.q) >= 0);
        return ret;
    }

    static BigInteger sm2_get_prikey() {
        return SM2Params.curve.randomFieldElementMult(rnd).toBigInteger();
    }

    static ECPoint sm2_get_pubkey(BigInteger prikey) {
        return SM2Params.g.multiply(prikey).normalize();
    }
}