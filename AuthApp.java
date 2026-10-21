import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Educational user-authentication program for SDEV 4303, Chapter 3.
 * Stores username:salt:SHA-256(password || salt) records in a text file.
 */
public class AuthApp {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final Console CONSOLE = System.console();

    private static final class UserRecord {
        final String salt;
        final String passwordHash;

        UserRecord(String salt, String passwordHash) {
            this.salt = salt;
            this.passwordHash = passwordHash;
        }
    }

    private static Path databasePath() {
        String configured = System.getenv("PASSWORD_DB");
        return (configured == null || configured.isBlank())
                ? Path.of("users.txt")
                : Path.of(configured);
    }

    private static String readLine(String prompt) {
        return CONSOLE.readLine("%s", prompt).trim();
    }

    private static char[] readPassword(String prompt) {
        return CONSOLE.readPassword("%s", prompt);
    }

    private static Map<String, UserRecord> loadUsers(Path path) throws IOException {
        Map<String, UserRecord> users = new HashMap<>();
        if (!Files.exists(path)) {
            return users;
        }
        int lineNumber = 0;
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            lineNumber++;
            if (line.isBlank()) {
                continue;
            }
            String[] fields = line.split(":", -1);
            if (fields.length != 3 || fields[0].isBlank()) {
                throw new IOException("Invalid record in database at line " + lineNumber + ".");
            }
            users.put(fields[0], new UserRecord(fields[1], fields[2]));
        }
        return users;
    }

    private static String createSalt() {
        byte[] bytes = new byte[16]; // 128 random bits
        RANDOM.nextBytes(bytes);
        return toHex(bytes);
    }

    private static String hashPassword(char[] password, String salt)
            throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        ByteBuffer encodedPassword = StandardCharsets.UTF_8.encode(
                java.nio.CharBuffer.wrap(password));
        byte[] passwordBytes = new byte[encodedPassword.remaining()];
        encodedPassword.get(passwordBytes);
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);
        try {
            // Hash the password concatenated with the salt, as required by the assignment.
            digest.update(passwordBytes);
            digest.update(saltBytes);
            return toHex(digest.digest());
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(saltBytes, (byte) 0);
        }
    }

    private static String toHex(byte[] bytes) {
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            result[i * 2] = HEX[value >>> 4];
            result[i * 2 + 1] = HEX[value & 0x0f];
        }
        return new String(result);
    }

    private static void appendUser(Path path, String username, String salt, String passwordHash)
            throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        String line = username + ":" + salt + ":" + passwordHash + System.lineSeparator();
        Files.writeString(path, line, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private static void register(Path path) throws IOException, GeneralSecurityException {
        Map<String, UserRecord> users = loadUsers(path);
        String username = readLine("Login name: ");
        if (username.isEmpty() || username.contains(":") || username.contains("\t")) {
            System.out.println("Login name cannot be empty or contain ':' or tabs.");
            return;
        }
        if (users.containsKey(username)) {
            System.out.println("That login name is already registered.");
            return;
        }

        char[] password = readPassword("Password: ");
        char[] confirmation = readPassword("Confirm password: ");
        try {
            if (password.length == 0) {
                System.out.println("Password cannot be empty.");
                return;
            }
            if (!Arrays.equals(password, confirmation)) {
                System.out.println("Passwords do not match.");
                return;
            }
            String salt = createSalt();
            String passwordHash = hashPassword(password, salt);
            appendUser(path, username, salt, passwordHash);
            System.out.println("Registration successful. The password itself was not stored.");
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    private static void login(Path path) throws IOException, GeneralSecurityException {
        Map<String, UserRecord> users = loadUsers(path);
        String username = readLine("Login name: ");
        char[] password = readPassword("Password: ");
        try {
            UserRecord user = users.get(username);
            if (user == null) {
                System.out.println("Login failed: invalid login name or password.");
                return;
            }
            String candidateHash = hashPassword(password, user.salt);
            boolean matches = MessageDigest.isEqual(
                    candidateHash.getBytes(StandardCharsets.US_ASCII),
                    user.passwordHash.getBytes(StandardCharsets.US_ASCII));
            if (matches) {
                System.out.println("Login successful. Welcome, " + username + ".");
            } else {
                System.out.println("Login failed: invalid login name or password.");
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public static void main(String[] args) {
        if (CONSOLE == null) {
            System.err.println("Run this program in a terminal so password input can be hidden.");
            return;
        }
        Path path = databasePath();
        while (true) {
            System.out.println("\n=== User Authentication Demo (Java) ===");
            System.out.println("1. Register");
            System.out.println("2. Log in");
            System.out.println("3. Exit");
            String choice = readLine("Choose an option: ");
            try {
                switch (choice) {
                    case "1" -> register(path);
                    case "2" -> login(path);
                    case "3" -> {
                        System.out.println("Goodbye.");
                        return;
                    }
                    default -> System.out.println("Please choose 1, 2, or 3.");
                }
            } catch (IOException | GeneralSecurityException error) {
                System.out.println("Operation could not be completed: " + error.getMessage());
            }
        }
    }
}
