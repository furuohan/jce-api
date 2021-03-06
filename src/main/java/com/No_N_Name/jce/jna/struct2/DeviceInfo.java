package com.No_N_Name.jce.jna.struct2;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import com.sun.jna.Structure;
import com.No_N_Name.jce.provider.utils.BytesUtil;

public class DeviceInfo {
    private static Logger logger;
    public byte[] issuerName = new byte[40];
    public byte[] deviceName = new byte[16];
    public byte[] deviceSerial = new byte[16];
    public int deviceVersion;
    public int standardVersion;
    public int[] asymAlgAbility = new int[2];
    public int symAlgAbility;
    public int hashAlgAbility;
    public int bufferSize;

    public DeviceInfo() {
    }

    public void decode(byte[] deviceData) {
        int offset = 0;
        System.arraycopy(deviceData, 0, this.issuerName, 0, 40);
        offset = offset + 40;
        System.arraycopy(deviceData, offset, this.deviceName, 0, 16);
        offset += 16;
        System.arraycopy(deviceData, offset, this.deviceSerial, 0, 16);
        offset += 16;
        this.deviceVersion = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.standardVersion = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.asymAlgAbility[0] = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.asymAlgAbility[1] = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.symAlgAbility = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.hashAlgAbility = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
        this.hashAlgAbility |= 191;
        this.bufferSize = BytesUtil.bytes2int(deviceData, offset);
        offset += 4;
    }

    protected List getFieldOrder() {
        return Arrays.asList("issuerName", "deviceName", "deviceSerial", "deviceVersion", "standardVersion", "asymAlgAbility", "symAlgAbility", "hashAlgAbility", "bufferSize");
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");
        buf.append("    |    Project          |   Value  ").append(nl);
        buf.append("   _|_____________________|______________________________________________________").append(nl);
        buf.append("   1| Issuer Name         | ").append(new String(this.issuerName)).append(nl);
        buf.append("   2| Device Name         | ").append(new String(this.deviceName)).append(nl);
        buf.append("   3| Device Serial       | ").append(new String(this.deviceSerial)).append(nl);
        buf.append("   4| Device Version      | ").append("v" + Integer.toHexString(this.deviceVersion)).append(nl);
        buf.append("   5| Standard version    | ").append("v" + Integer.toHexString(this.standardVersion)).append(nl);
        buf.append("   6| Asymmetric algorithm| ").append(getSuportAsymAlg(this.asymAlgAbility[0])).append(nl);
        buf.append("   7| Symmetric algorithm | ").append(getSuportSymAlg(this.symAlgAbility)).append(nl);
        buf.append("   8| Hash algorithm      | ").append(getSuportHashAlg(this.hashAlgAbility)).append(nl);
        buf.append("   9| User memory space   | ").append(this.bufferSize / 1024 + "KB").append(nl);
        return buf.toString();
    }

    private static String getSuportAsymAlg(int asymAlgAbility) {
        StringBuilder suportSymAlg = new StringBuilder();
        logger.fine("asymAlgAbility:" + asymAlgAbility);
        if ((asymAlgAbility & 65536 & -65536) != 0) {
            suportSymAlg.append(" RSA");
        }

        if ((asymAlgAbility & 131072 & -65536) != 0) {
            suportSymAlg.append(" SM2");
        }

        if ((asymAlgAbility & 262144 & -65536) != 0) {
            suportSymAlg.append(" DSA");
        }

        if ((asymAlgAbility & 524288 & -65536) != 0) {
            suportSymAlg.append(" ECDSA");
        }

        return suportSymAlg.toString();
    }

    private static String getSuportSymAlg(int symAlgAbility) {
        StringBuilder suportSymAlg = new StringBuilder();
        logger.fine("symAlgAbility:" + symAlgAbility);
        if ((symAlgAbility & 257 & -256) != 0) {
            suportSymAlg.append(" SM1");
        }

        if ((symAlgAbility & 513 & -256) != 0) {
            suportSymAlg.append(" SSF33");
        }

        if ((symAlgAbility & 1025 & -256) != 0) {
            suportSymAlg.append(" AES");
        }

        if ((symAlgAbility & 2049 & -256) != 0) {
            suportSymAlg.append(" 3DES");
        }

        if ((symAlgAbility & 8193 & -256) != 0) {
            suportSymAlg.append(" SM4");
        }

        if ((symAlgAbility & 16386 & -256) != 0) {
            suportSymAlg.append(" DES");
        }

        return suportSymAlg.toString();
    }

    private static String getSuportHashAlg(int hsahAlgAbility) {
        StringBuilder suportHashAlg = new StringBuilder();
        logger.fine("hsahAlgAbility:" + hsahAlgAbility);
        if ((hsahAlgAbility & 1) != 0) {
            suportHashAlg.append(" SM3");
        }

        if ((hsahAlgAbility & 2) != 0) {
            suportHashAlg.append(" SHA1");
        }

        if ((hsahAlgAbility & 4) != 0) {
            suportHashAlg.append(" SHA256");
        }

        if ((hsahAlgAbility & 8) != 0) {
            suportHashAlg.append(" SHA512");
        }

        if ((hsahAlgAbility & 16) != 0) {
            suportHashAlg.append(" SHA384");
        }

        if ((hsahAlgAbility & 32) != 0) {
            suportHashAlg.append(" SHA224");
        }

        if ((hsahAlgAbility & 128) != 0) {
            suportHashAlg.append(" MD5");
        }

        return suportHashAlg.toString();
    }

    static {
      //  logger = CryptoLogger.logger;
    }

    public static class ByReference extends DeviceInfo implements Structure.ByReference {
        public ByReference() {
        }
    }
}
