package ru.sakhapov;

import java.net.InetAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLCertificateScanner {

    public void scanIPRange(String ipRange, int threadCount) {
        String[] ips = ipRange.split("-");
        String startIP = ips[0];
        String endIP = ips[1];

        try {
            InetAddress startAddress = InetAddress.getByName(startIP);
            InetAddress endAddress = InetAddress.getByName(endIP);

            int start = byteArrayToInt(startAddress.getAddress());
            int end = byteArrayToInt(endAddress.getAddress());

            int totalIPs = end - start + 1;
            int ipsPerThread = totalIPs / threadCount;

            for (int i = 0; i < threadCount; i++) {
                int threadStart = start + (i * ipsPerThread);
                int threadEnd = threadStart + ipsPerThread - 1;

                if (i == threadCount - 1) {
                    threadEnd = end;
                }

                Thread thread = new Thread(new IPRangeScanner(threadStart, threadEnd));
                thread.start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private int byteArrayToInt(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }

    private static class IPRangeScanner implements Runnable {
        private final int startIP;
        private final int endIP;

        public IPRangeScanner(int startIP, int endIP) {
            this.startIP = startIP;
            this.endIP = endIP;
        }

        @Override
        public void run() {
            try {
                for (int ip = startIP; ip <= endIP; ip++) {
                    InetAddress address = InetAddress.getByAddress(intToByteArray(ip));
                    scanIPAddress(address);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void scanIPAddress(InetAddress address) {
            try {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) factory.createSocket(address, 443);
                socket.startHandshake();

                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, null, null);
                SSLSession session = socket.getSession();
                Certificate[] certificates = session.getPeerCertificates();

                for (Certificate certificate : certificates) {
                    if (certificate instanceof X509Certificate) {
                        X509Certificate x509Certificate = (X509Certificate) certificate;
                        String[] domainNames = x509Certificate.getSubjectAlternativeNames()
                                .stream()
                                .filter(entry -> entry.get(0).equals(2))
                                .map(entry -> (String) entry.get(1))
                                .toArray(String[]::new);

                        for (String domainName : domainNames) {
                            System.out.println("Название домена: " + domainName);
                        }
                    }
                }

                socket.close();
            } catch (Exception ignored) {
            }
        }

        private byte[] intToByteArray(int value) {
            byte[] bytes = new byte[4];
            bytes[0] = (byte) (value >> 24);
            bytes[1] = (byte) (value >> 16);
            bytes[2] = (byte) (value >> 8);
            bytes[3] = (byte) value;
            return bytes;
        }
    }

    public static void main(String[] args) {
        SSLCertificateScanner scanner = new SSLCertificateScanner();
        String ipRange = "51.38.24.0-51.38.24.255";
        int threadCount = 4;
        scanner.scanIPRange(ipRange, threadCount);
    }
}