package org.evocraft.evovote.vote;

import net.minecraft.server.MinecraftServer;
import net.minecraftforge.fml.loading.FMLPaths;
import net.minecraftforge.server.ServerLifecycleHooks;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EvoVotifier {

    private static final int PORT = 8192; // Rămâne pe 8192 cum ai setat în Pterodactyl!
    private static PrivateKey privateKey;
    private static ServerSocket serverSocket;
    private static ExecutorService workerPool;
    private static volatile boolean isRunning = false;

    public static synchronized void start() {
        if (isRunning) return;

        try {
            loadOrGenerateKeys();

            serverSocket = new ServerSocket(PORT);
            workerPool = Executors.newFixedThreadPool(4, r -> {
                Thread t = new Thread(r, "EvoVotifier-Worker");
                t.setDaemon(true);
                return t;
            });
            isRunning = true;

            System.out.println("[EvoVotifier] Vote system started on port " + PORT + "!");

            Thread acceptThread = new Thread(() -> {
                while (isRunning) {
                    try {
                        Socket socket = serverSocket.accept();
                        socket.setSoTimeout(5000); // 5 secunde timeout pentru fiecare conexiune

                        ExecutorService pool = workerPool;
                        if (pool != null && !pool.isShutdown()) {
                            pool.execute(() -> {
                                try {
                                    handleVoteConnection(socket);
                                } catch (Exception ignored) {
                                }
                            });
                        } else {
                            socket.close();
                        }

                    } catch (Exception e) {
                        if (isRunning && serverSocket != null && !serverSocket.isClosed()) {
                            System.err.println("[EvoVotifier] Error while accepting connection: " + e.getMessage());
                        }
                    }
                }
            }, "EvoVotifier-Main-Thread");
            acceptThread.setDaemon(true);
            acceptThread.start();

        } catch (Exception e) {
            System.err.println("[EvoVotifier] CRITICAL ERROR: Could not start vote system!");
            e.printStackTrace();
        }
    }

    public static synchronized void stop() {
        isRunning = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            serverSocket = null;
        }
        if (workerPool != null) {
            workerPool.shutdownNow();
            workerPool = null;
        }
    }

    private static void handleVoteConnection(Socket socket) throws Exception {
        try (socket) {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
            writer.write("VOTIFIER 1.9\n");
            writer.flush();

            InputStream in = socket.getInputStream();
            byte[] block = new byte[256];
            int read = 0;
            while (read < 256) {
                int r = in.read(block, read, 256 - read);
                if (r == -1) break;
                read += r;
            }

            if (read == 256) {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                String data = new String(cipher.doFinal(block), StandardCharsets.UTF_8);

                String[] parts = data.split("\n");
                if (parts.length >= 5 && "VOTE".equals(parts[0].trim())) {
                    String username = parts[2].trim();
                    if (!username.matches("^[A-Za-z0-9_]{1,16}$")) {
                        System.err.println("[EvoVotifier] Rejected malformed vote username.");
                        return;
                    }

                    MinecraftServer server = ServerLifecycleHooks.getCurrentServer();
                    if (server != null) {
                        server.execute(() -> {
                            System.out.println("[EvoVotifier] Received a valid vote for: " + username);
                            server.getCommands().performPrefixedCommand(server.createCommandSourceStack(), "adminvote " + username);
                        });
                    }
                }
            }
        }
    }

    private static void loadOrGenerateKeys() throws Exception {
        File dir = FMLPaths.CONFIGDIR.get().resolve("evocore/votifier").toFile();
        if (!dir.exists()) dir.mkdirs();

        File pubFile = new File(dir, "public.key");
        File privFile = new File(dir, "private.key");

        if (!pubFile.exists() || !privFile.exists()) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();

            Files.writeString(pubFile.toPath(), Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
            Files.writeString(privFile.toPath(), Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
            privateKey = pair.getPrivate();
        } else {
            byte[] privBytes = Base64.getDecoder().decode(Files.readString(privFile.toPath()).trim());
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(privSpec);
        }
    }
}
