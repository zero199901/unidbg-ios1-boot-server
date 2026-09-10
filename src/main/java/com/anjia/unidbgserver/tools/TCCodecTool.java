package com.anjia.unidbgserver.tools;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.anjia.unidbgserver.service.TTEncryptServiceWorker;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * tc 协议编解码工具
 *
 * 功能:
 *   1. tc-decode: 解压 tc 协议数据
 *   2. tc-encode: 压缩并生成 tc 协议数据
 *   3. 修改设备指纹
 *
 * 使用:
 *   mvn exec:java -Dexec.mainClass="com.anjia.unidbgserver.tools.TCCodecTool" \
 *     -Dexec.args="decode input.bin output.bin"
 */
public class TCCodecTool {

    private static final String DEFAULT_IPA_PATH = "research/豆包-11.8.0.ipa";
    private static final String IPA_PATH_PROPERTY = "ipa.path";

    private static TTEncryptServiceWorker worker;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String command = args[0];

        initWorker();
        try {
            switch (command) {
                case "decode":
                    if (args.length < 3) {
                        throw new IllegalArgumentException("用法: decode <input.tc> <output.bin>");
                    }
                    decodeTc(args[1], args[2]);
                    break;

                case "encode":
                    if (args.length < 3) {
                        throw new IllegalArgumentException("用法: encode <input.bin> <output.tc>");
                    }
                    encodeTc(args[1], args[2]);
                    break;

                case "modify":
                    if (args.length < 4) {
                        throw new IllegalArgumentException("用法: modify <input.tc> <output.tc> <new_device_id>");
                    }
                    modifyDeviceId(args[1], args[2], args[3]);
                    break;

                default:
                    printUsage();
                    throw new IllegalArgumentException("未知命令: " + command);
            }
        } finally {
            worker.destroy();
        }
    }

    private static void initWorker() throws Exception {
        String ipaPath = System.getProperty(IPA_PATH_PROPERTY, DEFAULT_IPA_PATH);
        if (!Files.isRegularFile(Paths.get(ipaPath))) {
            throw new IllegalArgumentException("IPA 文件不存在: " + ipaPath
                + "；请通过 -D" + IPA_PATH_PROPERTY + "=/absolute/path/to/app.ipa 指定路径");
        }

        System.out.println("初始化 unidbg，IPA: " + ipaPath);
        UnidbgProperties props = new UnidbgProperties();
        props.setIpaPath(ipaPath);
        props.setDynarmic(false);
        props.setVerbose(false);
        // CLI 只使用一个同步 worker，避免在非 Spring 环境中创建未配置的线程池。
        props.setAsync(false);

        worker = new TTEncryptServiceWorker(props);
        System.out.println("✅ 初始化完成\n");
    }

    /**
     * 解码 tc 协议
     */
    private static void decodeTc(String inputFile, String outputFile) throws Exception {
        System.out.println("=" .repeat(80));
        System.out.println("tc 协议解码");
        System.out.println("=" .repeat(80));

        // 读取 tc 数据
        byte[] tcData = Files.readAllBytes(Paths.get(inputFile));
        System.out.println("输入文件: " + inputFile);
        System.out.println("tc 数据大小: " + tcData.length + " 字节");

        if (tcData.length < 8) {
            throw new RuntimeException("tc 数据太短");
        }

        // 解析头部
        String magic = new String(new byte[]{tcData[0], tcData[1]});
        String version = bytesToHex(tcData, 2, 2);
        String metadata = bytesToHex(tcData, 4, 4);

        System.out.println("\ntc 头部:");
        System.out.println("  magic:    " + magic);
        System.out.println("  version:  " + version);
        System.out.println("  metadata: " + metadata);

        // 提取 bvx2 payload
        byte[] bvx2Payload = new byte[tcData.length - 8];
        System.arraycopy(tcData, 8, bvx2Payload, 0, bvx2Payload.length);
        System.out.println("  payload:  " + bvx2Payload.length + " 字节\n");

        // 解压
        System.out.println("解压 bvx2...");
        byte[] decompressed = worker.decompressBVX2(bvx2Payload).get();

        System.out.println("✅ 解压成功!");
        System.out.println("   解压后大小: " + decompressed.length + " 字节");
        System.out.println("   前100字节: " + bytesToHex(decompressed, 0, Math.min(100, decompressed.length)));

        // 保存
        Files.write(Paths.get(outputFile), decompressed);
        System.out.println("\n✅ 已保存到: " + outputFile);
    }

    /**
     * 编码 tc 协议
     */
    private static void encodeTc(String inputFile, String outputFile) throws Exception {
        System.out.println("=" .repeat(80));
        System.out.println("tc 协议编码");
        System.out.println("=" .repeat(80));

        // 读取 Protobuf 数据
        byte[] protobufData = Files.readAllBytes(Paths.get(inputFile));
        System.out.println("输入文件: " + inputFile);
        System.out.println("Protobuf 大小: " + protobufData.length + " 字节\n");

        // 压缩（这里需要实现 bvx2 压缩）
        System.out.println("压缩 bvx2...");
        byte[] compressed = compressBVX2(protobufData);

        System.out.println("✅ 压缩成功!");
        System.out.println("   压缩后大小: " + compressed.length + " 字节");

        // 添加 tc 头部
        byte[] tcData = new byte[8 + compressed.length];

        // magic "tc"
        tcData[0] = 't';
        tcData[1] = 'c';

        // version 0x0510
        tcData[2] = 0x05;
        tcData[3] = 0x10;

        // metadata 0x0000c761
        tcData[4] = 0x00;
        tcData[5] = 0x00;
        tcData[6] = (byte) 0xc7;
        tcData[7] = 0x61;

        // payload
        System.arraycopy(compressed, 0, tcData, 8, compressed.length);

        System.out.println("   tc 总大小: " + tcData.length + " 字节");

        // 保存
        Files.write(Paths.get(outputFile), tcData);
        System.out.println("\n✅ 已保存到: " + outputFile);
    }

    /**
     * 修改设备 ID
     */
    private static void modifyDeviceId(String inputFile, String outputFile, String newDeviceId) throws Exception {
        System.out.println("=" .repeat(80));
        System.out.println("修改设备 ID");
        System.out.println("=" .repeat(80));

        System.out.println("输入: " + inputFile);
        System.out.println("输出: " + outputFile);
        System.out.println("新 device_id: " + newDeviceId + "\n");

        // 1. 解码
        byte[] tcData = Files.readAllBytes(Paths.get(inputFile));
        byte[] bvx2Payload = new byte[tcData.length - 8];
        System.arraycopy(tcData, 8, bvx2Payload, 0, bvx2Payload.length);

        System.out.println("解压 bvx2...");
        byte[] protobufData = worker.decompressBVX2(bvx2Payload).get();
        System.out.println("✅ 解压成功: " + protobufData.length + " 字节\n");

        // 2. 修改 Protobuf (这里需要解析和修改)
        System.out.println("修改 Protobuf 字段...");
        byte[] modifiedProtobuf = modifyProtobufDeviceId(protobufData, newDeviceId);
        System.out.println("✅ 修改成功\n");

        // 3. 重新编码
        System.out.println("重新压缩...");
        byte[] compressed = compressBVX2(modifiedProtobuf);

        // 添加 tc 头部
        byte[] newTcData = new byte[8 + compressed.length];
        System.arraycopy(tcData, 0, newTcData, 0, 8);  // 复用原头部
        System.arraycopy(compressed, 0, newTcData, 8, compressed.length);

        // 保存
        Files.write(Paths.get(outputFile), newTcData);
        System.out.println("✅ 已保存到: " + outputFile);
    }

    /**
     * 压缩 bvx2（调用 unidbg）
     */
    private static byte[] compressBVX2(byte[] data) throws Exception {
        // TODO: 实现 bvx2 压缩
        // 需要调用 libcompression.dylib 的 compression_encode_buffer
        throw new UnsupportedOperationException("bvx2 压缩尚未实现");
    }

    /**
     * 修改 Protobuf 中的 device_id
     */
    private static byte[] modifyProtobufDeviceId(byte[] protobufData, String newDeviceId) throws Exception {
        // TODO: 解析并修改 Protobuf
        // 需要:
        //   1. 解析 Protobuf wire format
        //   2. 找到 device_id 字段
        //   3. 修改值
        //   4. 重新序列化
        throw new UnsupportedOperationException("Protobuf 修改尚未实现");
    }

    private static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length && (offset + i) < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    private static void printUsage() {
        System.out.println("tc 协议编解码工具");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  decode   <input.tc> <output.bin>              解码 tc 协议");
        System.out.println("  encode   <input.bin> <output.tc>              编码 tc 协议");
        System.out.println("  modify   <input.tc> <output.tc> <device_id>   修改设备 ID");
        System.out.println();
        System.out.println("示例:");
        System.out.println("  mvn exec:java -Dipa.path=/absolute/path/to/app.ipa \\");
        System.out.println("    -Dexec.mainClass=\"com.anjia.unidbgserver.tools.TCCodecTool\" \\");
        System.out.println("    -Dexec.args=\"decode /tmp/tc_original.bin /tmp/tc_decoded.bin\"");
    }
}
