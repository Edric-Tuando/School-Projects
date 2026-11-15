import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Queue;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class CybersecurityV2 {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            IncidentManager manager = new IncidentManager("incidents.db");
            AccountManager accounts;
            try {
                accounts = new AccountManager(manager.getConnection());
            } catch (DatabaseException e) {
                JOptionPane.showMessageDialog(null, e.getMessage() + "\nAccounts will not be saved.",
                        "Database error", JOptionPane.WARNING_MESSAGE);
                accounts = new AccountManager(null);
            }
            UserAccount account = LoginDialog.ask(null, accounts);
            if (account == null) {
                manager.close();
                System.exit(0);
            }
            new IncidentApp(manager, accounts, account).setVisible(true);
        });
    }
}

enum Role { ADMIN, USER }

class UserAccount {
    private final String username;
    private final String fullName;
    private final String salt;
    private final String passwordHash;
    private final Role role;

    UserAccount(String username, String fullName, String salt, String passwordHash, Role role) {
        this.username = username;
        this.fullName = fullName;
        this.salt = salt;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    String getUsername() { return username; }
    String getFullName() { return fullName; }
    String getSalt() { return salt; }
    String getPasswordHash() { return passwordHash; }
    Role getRole() { return role; }
}

// Accounts are kept in a HashMap and saved to the users table in SQLite
class AccountManager {
    private static final int MAX_ATTEMPTS = 3;
    private static final long LOCK_MILLIS = 30_000;

    private final HashMap<String, UserAccount> accounts = new HashMap<>();
    private final HashMap<String, Integer> failedAttempts = new HashMap<>();
    private final HashMap<String, Long> lockedUntil = new HashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final Connection connection; // null means accounts live in memory only

    AccountManager(Connection connection) {
        this.connection = connection;
        if (connection != null) {
            loadAccounts();
        }
        if (!accounts.containsKey("admin")) {
            String salt = newSalt();
            UserAccount admin = new UserAccount("admin", "Administrator", salt,
                    hash("admin123", salt), Role.ADMIN);
            store(admin);
            accounts.put("admin", admin);
        }
    }

    UserAccount register(String fullName, String username, String password, String confirm)
            throws InvalidInputException {
        fullName = fullName == null ? "" : fullName.trim();
        username = username == null ? "" : username.trim();
        if (fullName.isEmpty()) {
            throw new InvalidInputException("Full name cannot be empty.");
        }
        if (!username.matches("[A-Za-z0-9_]{3,20}")) {
            throw new InvalidInputException(
                    "Username must be 3-20 characters: letters, numbers or underscore only.");
        }
        if (accounts.containsKey(username.toLowerCase())) {
            throw new InvalidInputException("That username is already taken.");
        }
        if (password.length() < 8 || !password.matches(".*[A-Za-z].*") || !password.matches(".*[0-9].*")) {
            throw new InvalidInputException(
                    "Password must be at least 8 characters and include a letter and a number.");
        }
        if (!password.equals(confirm)) {
            throw new InvalidInputException("Passwords do not match.");
        }
        String salt = newSalt();
        UserAccount account = new UserAccount(username, fullName, salt, hash(password, salt), Role.USER);
        store(account);
        accounts.put(username.toLowerCase(), account);
        return account;
    }

    UserAccount authenticate(String username, String password) throws InvalidInputException {
        String key = username == null ? "" : username.trim().toLowerCase();
        Long until = lockedUntil.get(key);
        long now = System.currentTimeMillis();
        if (until != null && now < until) {
            throw new InvalidInputException("Too many failed attempts. Try again in "
                    + ((until - now) / 1000 + 1) + " seconds.");
        }
        UserAccount account = accounts.get(key);
        boolean ok = account != null && MessageDigest.isEqual(
                hash(password, account.getSalt()).getBytes(StandardCharsets.UTF_8),
                account.getPasswordHash().getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            int fails = failedAttempts.merge(key, 1, Integer::sum);
            if (fails >= MAX_ATTEMPTS) {
                lockedUntil.put(key, now + LOCK_MILLIS);
                failedAttempts.remove(key);
            }
            throw new InvalidInputException("Incorrect username or password.");
        }
        failedAttempts.remove(key);
        lockedUntil.remove(key);
        return account;
    }

    List<UserAccount> all() {
        List<UserAccount> list = new ArrayList<>(accounts.values());
        list.sort(Comparator.comparing(UserAccount::getUsername, String.CASE_INSENSITIVE_ORDER));
        return list;
    }

    void remove(String username) throws InvalidInputException {
        UserAccount account = accounts.get(username.toLowerCase());
        if (account == null) {
            throw new InvalidInputException("Account not found.");
        }
        if (account.getRole() == Role.ADMIN) {
            throw new InvalidInputException("The admin account cannot be removed.");
        }
        if (connection != null) {
            try (PreparedStatement ps = connection.prepareStatement("DELETE FROM users WHERE username = ?")) {
                ps.setString(1, account.getUsername());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new DatabaseException("Could not remove the account: " + e.getMessage(), e);
            }
        }
        accounts.remove(username.toLowerCase());
    }

    private void loadAccounts() {
        try (Statement st = connection.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, full_name TEXT NOT NULL, "
                    + "salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL)");
            try (ResultSet rs = st.executeQuery(
                    "SELECT username, full_name, salt, password_hash, role FROM users")) {
                while (rs.next()) {
                    UserAccount a = new UserAccount(rs.getString(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), Role.valueOf(rs.getString(5)));
                    accounts.put(a.getUsername().toLowerCase(), a);
                }
            }
        } catch (SQLException e) {
            throw new DatabaseException("Could not load the accounts: " + e.getMessage(), e);
        }
    }

    private void store(UserAccount a) {
        if (connection == null) {
            return;
        }
        String sql = "INSERT INTO users (username, full_name, salt, password_hash, role) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, a.getUsername());
            ps.setString(2, a.getFullName());
            ps.setString(3, a.getSalt());
            ps.setString(4, a.getPasswordHash());
            ps.setString(5, a.getRole().name());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Could not save the account: " + e.getMessage(), e);
        }
    }

    private String newSalt() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String hash(String password, String salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                    Base64.getDecoder().decode(salt), 65536, 256);
            byte[] bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password hashing is not available.", e);
        }
    }
}

class LoginDialog extends JDialog {
    private static final String HINT = "Password: at least 8 characters, with a letter and a number.";

    private final AccountManager accounts;
    private UserAccount result;

    private final JTabbedPane tabs = new JTabbedPane();
    private final JTextField loginUser = new JTextField(18);
    private final JPasswordField loginPass = new JPasswordField(18);
    private final JLabel loginMsg = new JLabel(" ");
    private final JTextField regName = new JTextField(18);
    private final JTextField regUser = new JTextField(18);
    private final JPasswordField regPass = new JPasswordField(18);
    private final JPasswordField regConfirm = new JPasswordField(18);
    private final JLabel regMsg = new JLabel(" ");
    private final JCheckBox showLogin = new JCheckBox("Show password");
    private final JCheckBox showRegister = new JCheckBox("Show password");
    private final char dots = new JPasswordField().getEchoChar();
    private final RoundButton loginBtn = new RoundButton("Log in", Theme.BRAND, Color.WHITE);
    private final RoundButton registerBtn = new RoundButton("Create account", Theme.LOW, Color.WHITE);

    static UserAccount ask(Component parent, AccountManager accounts) {
        Window owner = parent == null ? null : SwingUtilities.getWindowAncestor(parent);
        LoginDialog dialog = new LoginDialog(owner, accounts);
        dialog.setVisible(true);
        return dialog.result;
    }

    private LoginDialog(Window owner, AccountManager accounts) {
        super(owner, "Cybersecurity Incident System", Dialog.ModalityType.APPLICATION_MODAL);
        this.accounts = accounts;
        getContentPane().setBackground(Theme.BG);
        setLayout(new BorderLayout());

        JPanel banner = new JPanel() {
            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                g.setPaint(new GradientPaint(0, 0, Theme.BRAND, getWidth(), 0, new Color(0x2F7AB8)));
                g.fillRect(0, 0, getWidth(), getHeight());
                g.dispose();
            }
        };
        banner.setLayout(new BoxLayout(banner, BoxLayout.Y_AXIS));
        banner.setBorder(BorderFactory.createEmptyBorder(18, 22, 16, 22));
        JLabel title = new JLabel("Cybersecurity Incident System");
        title.setFont(Theme.BASE.deriveFont(Font.BOLD, 20f));
        title.setForeground(Color.WHITE);
        JLabel sub = new JLabel("Log in or create an account to continue");
        sub.setFont(Theme.BASE);
        sub.setForeground(new Color(0xD6E6F5));
        banner.add(title);
        banner.add(sub);

        showLogin.addActionListener(e -> loginPass.setEchoChar(showLogin.isSelected() ? (char) 0 : dots));
        showRegister.addActionListener(e -> {
            char echo = showRegister.isSelected() ? (char) 0 : dots;
            regPass.setEchoChar(echo);
            regConfirm.setEchoChar(echo);
        });

        tabs.setFont(Theme.BOLD);
        tabs.addTab("Log in", form(new String[]{"Username", "Password"},
                new JComponent[]{loginUser, loginPass}, showLogin, loginMsg, loginBtn));
        tabs.addTab("Create account", form(new String[]{"Full name", "Username", "Password", "Confirm password"},
                new JComponent[]{regName, regUser, regPass, regConfirm}, showRegister, regMsg, registerBtn));
        tabs.addChangeListener(e ->
                getRootPane().setDefaultButton(tabs.getSelectedIndex() == 0 ? loginBtn : registerBtn));
        showMessage(regMsg, HINT, Theme.MUTED);

        JPanel body = new JPanel(new BorderLayout());
        body.setOpaque(false);
        body.setBorder(BorderFactory.createEmptyBorder(12, 16, 16, 16));
        body.add(tabs, BorderLayout.CENTER);
        add(banner, BorderLayout.NORTH);
        add(body, BorderLayout.CENTER);

        loginBtn.addActionListener(e -> doLogin());
        registerBtn.addActionListener(e -> doRegister());
        getRootPane().setDefaultButton(loginBtn);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(false);
        pack();
        setLocationRelativeTo(owner);
    }

    private JPanel form(String[] labels, JComponent[] fields, JCheckBox show, JLabel msg, JComponent button) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBackground(Color.WHITE);
        p.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0;
        g.weightx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.insets = new Insets(3, 0, 3, 0);
        int y = 0;
        for (int i = 0; i < labels.length; i++) {
            JLabel label = new JLabel(labels[i]);
            label.setFont(Theme.BOLD.deriveFont(12f));
            label.setForeground(Theme.MUTED);
            g.gridy = y++;
            p.add(label, g);
            fields[i].setFont(Theme.BASE);
            fields[i].setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(Theme.LINE),
                    BorderFactory.createEmptyBorder(5, 8, 5, 8)));
            g.gridy = y++;
            p.add(fields[i], g);
        }
        show.setOpaque(false);
        show.setFont(Theme.BASE);
        g.gridy = y++;
        p.add(show, g);
        msg.setFont(Theme.BASE);
        g.insets = new Insets(8, 0, 6, 0);
        g.gridy = y++;
        p.add(msg, g);
        g.insets = new Insets(3, 0, 3, 0);
        g.gridy = y;
        p.add(button, g);
        return p;
    }

    private void showMessage(JLabel label, String text, Color color) {
        label.setText("<html><body style='width:230px'>" + text + "</body></html>");
        label.setForeground(color);
    }

    private void doLogin() {
        try {
            result = accounts.authenticate(loginUser.getText(), new String(loginPass.getPassword()));
            dispose();
        } catch (InvalidInputException ex) {
            loginPass.setText("");
            showMessage(loginMsg, ex.getMessage(), Theme.CRITICAL);
        }
    }

    private void doRegister() {
        try {
            accounts.register(regName.getText(), regUser.getText(),
                    new String(regPass.getPassword()), new String(regConfirm.getPassword()));
            String username = regUser.getText().trim();
            regName.setText("");
            regUser.setText("");
            regPass.setText("");
            regConfirm.setText("");
            showMessage(regMsg, HINT, Theme.MUTED);
            loginUser.setText(username);
            loginPass.setText("");
            showMessage(loginMsg, "Account created. Log in to continue.", Theme.LOW);
            tabs.setSelectedIndex(0);
            loginPass.requestFocusInWindow();
        } catch (InvalidInputException | DatabaseException ex) {
            regPass.setText("");
            regConfirm.setText("");
            showMessage(regMsg, ex.getMessage(), Theme.CRITICAL);
        }
    }
}

// ================= Custom exceptions =================
class InvalidInputException extends Exception {
    public InvalidInputException(String message) {
        super(message);
    }
}

class IncidentNotFoundException extends Exception {
    public IncidentNotFoundException(int id) {
        super("Incident not found (ID: " + id + ").");
    }
}

class IncidentClosedException extends Exception {
    public IncidentClosedException(String message) {
        super(message);
    }
}

// ================= Interfaces =================
interface Reportable {
    String generateReport();
}

interface Escalatable {
    boolean requiresEscalation();
}

// ================= Abstract parent class =================
abstract class SecurityIncident implements Reportable, Escalatable {
    // Encapsulation: private fields with getters and setters
    private int id;
    private String reporter;
    private String description;
    private String severity;
    private String status;

    public SecurityIncident(int id, String reporter, String description, String severity) {
        this.id = id;
        this.reporter = reporter;
        this.description = description;
        this.severity = severity;
        this.status = "Open";
    }

    public int getId() { return id; }
    public String getReporter() { return reporter; }
    public String getDescription() { return description; }
    public String getSeverity() { return severity; }
    public String getStatus() { return status; }

    public void setReporter(String reporter) { this.reporter = reporter; }
    public void setDescription(String description) { this.description = description; }
    public void setSeverity(String severity) { this.severity = severity; }
    public void setStatus(String status) { this.status = status; }

    // Abstract methods: each subclass overrides these (polymorphism)
    public abstract String getIncidentType();
    public abstract String recommendResponse();
    public abstract int getBaseRiskScore();

    public int calculateRiskScore() {
        int weight;
        switch (severity) {
            case "Medium": weight = 1; break;
            case "High": weight = 2; break;
            case "Critical": weight = 3; break;
            default: weight = 0;
        }
        return getBaseRiskScore() + weight;
    }

    @Override
    public boolean requiresEscalation() {
        return severity.equals("High") || severity.equals("Critical");
    }

    @Override
    public String generateReport() {
        return "#" + id + " [" + getIncidentType() + "] Severity: " + severity
                + " | Status: " + status + " | Reporter: " + reporter;
    }

    // Overloaded method: describe() and describe(boolean)
    public String describe() {
        return "Incident ID: " + id
                + "\nType: " + getIncidentType()
                + "\nReporter: " + reporter
                + "\nDescription: " + description
                + "\nSeverity: " + severity
                + "\nStatus: " + status
                + "\nRisk Score: " + calculateRiskScore()
                + "\nRecommended Response: " + recommendResponse();
    }

    public String describe(boolean brief) {
        return brief ? generateReport() : describe();
    }
}

// ================= Subclasses (inheritance) =================
class MalwareIncident extends SecurityIncident {
    public MalwareIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() { return "Malware"; }

    @Override
    public String recommendResponse() {
        return "Isolate the affected device and scan it using approved security software.";
    }

    @Override
    public int getBaseRiskScore() { return 7; }
}

class PhishingIncident extends SecurityIncident {
    public PhishingIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() { return "Phishing"; }

    @Override
    public String recommendResponse() {
        return "Avoid clicking suspicious links and report the message to the security team.";
    }

    @Override
    public int getBaseRiskScore() { return 5; }
}

class UnauthorizedAccessIncident extends SecurityIncident {
    public UnauthorizedAccessIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() { return "Unauthorized Access"; }

    @Override
    public String recommendResponse() {
        return "Review access logs, secure the affected account, and investigate suspicious activity.";
    }

    @Override
    public int getBaseRiskScore() { return 8; }
}

// ================= Data manager (collections, validation and SQLite storage) =================
class DatabaseException extends RuntimeException {
    public DatabaseException(String message, Throwable cause) {
        super(message, cause);
    }
}

class IncidentManager {
    public static final String[] TYPES = {"Malware", "Phishing", "Unauthorized Access"};
    public static final String[] SEVERITIES = {"Low", "Medium", "High", "Critical"};
    public static final String[] STATUSES = {"Open", "Under Investigation", "Resolved", "Closed"};

    private final ArrayList<SecurityIncident> incidents = new ArrayList<>();
    private final HashMap<Integer, SecurityIncident> incidentMap = new HashMap<>();
    private final Queue<SecurityIncident> escalationQueue = new LinkedList<>();
    private int nextId = 1; // only used when there is no database

    private Connection connection; // null means the app runs without a database
    private String storageInfo;
    private String startupWarning;

    public IncidentManager(String dbFile) {
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
            try (Statement st = connection.createStatement()) {
                st.execute("CREATE TABLE IF NOT EXISTS incidents ("
                        + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        + "type TEXT NOT NULL, reporter TEXT NOT NULL, description TEXT NOT NULL, "
                        + "severity TEXT NOT NULL, status TEXT NOT NULL, queue_order INTEGER)");
            }
            loadFromDatabase();
            storageInfo = "Saved in " + dbFile;
        } catch (SQLException | LinkageError e) {
            connection = null;
            incidents.clear();
            incidentMap.clear();
            escalationQueue.clear();
            storageInfo = "No database, changes are not saved";
            startupWarning = "Could not open the SQLite database, so the app is running without saving.\n"
                    + "Make sure the sqlite-jdbc and slf4j-api jar files are added to the project.\n\n"
                    + "Details: " + e.getMessage();
        }
    }

    public String getStorageInfo() { return storageInfo; }
    public Connection getConnection() { return connection; }

    public String takeStartupWarning() {
        String warning = startupWarning;
        startupWarning = null;
        return warning;
    }

    public void close() {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ignored) {
                // nothing more to do while closing
            }
        }
    }

    // Create
    public SecurityIncident report(String type, String reporter, String description, String severity)
            throws InvalidInputException {
        requireOneOf(type, TYPES, "Invalid incident type.");
        reporter = requireText(reporter, "Reporter name cannot be empty.");
        description = requireText(description, "Incident description cannot be empty.");
        requireOneOf(severity, SEVERITIES, "Invalid severity choice.");

        int id = insertRow(type, reporter, description, severity);
        SecurityIncident incident = create(type, id, reporter, description, severity);
        incidents.add(incident);
        incidentMap.put(id, incident);
        queueIfNeeded(incident);
        saveQueue();
        return incident;
    }

    // Read
    public SecurityIncident find(int id) throws IncidentNotFoundException {
        SecurityIncident incident = incidentMap.get(id);
        if (incident == null) {
            throw new IncidentNotFoundException(id);
        }
        return incident;
    }

    public List<SecurityIncident> getIncidents() {
        return new ArrayList<>(incidents);
    }

    // Update
    public void update(int id, String reporter, String description, String severity, String status)
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        SecurityIncident incident = find(id);
        if (incident.getStatus().equals("Closed")) {
            throw new IncidentClosedException("This incident is closed and can no longer be changed.");
        }
        reporter = requireText(reporter, "Reporter name cannot be empty.");
        description = requireText(description, "Incident description cannot be empty.");
        requireOneOf(severity, SEVERITIES, "Invalid severity choice.");
        requireOneOf(status, STATUSES, "Invalid status choice.");

        incident.setReporter(reporter);
        incident.setDescription(description);
        incident.setSeverity(severity);
        incident.setStatus(status);

        if (status.equals("Closed") || status.equals("Resolved")) {
            escalationQueue.remove(incident);
        } else {
            queueIfNeeded(incident);
        }
        saveRow(incident);
        saveQueue();
    }

    // Delete
    public void delete(int id) throws IncidentNotFoundException {
        SecurityIncident incident = find(id);
        deleteRow(id);
        incidents.remove(incident);
        incidentMap.remove(id);
        escalationQueue.remove(incident);
        saveQueue();
    }

    public String processNextEscalation() {
        SecurityIncident incident;
        while ((incident = escalationQueue.poll()) != null) {
            if (!incident.getStatus().equals("Closed") && incident.requiresEscalation()) {
                String details = incident.describe();
                boolean changed = incident.getStatus().equals("Open");
                if (changed) {
                    incident.setStatus("Under Investigation");
                    saveRow(incident);
                }
                saveQueue();
                return "Escalating next incident for review:\n\n" + details
                        + (changed ? "\n\nStatus changed to Under Investigation." : "")
                        + "\n\nIncidents still waiting in queue: " + escalationQueue.size();
            }
        }
        saveQueue();
        return "No incidents are waiting for escalation.";
    }

    // Dashboard values
    public int getTotal() { return incidents.size(); }
    public int getQueueSize() { return escalationQueue.size(); }

    public int countActive() {
        int count = 0;
        for (SecurityIncident incident : incidents) {
            if (!incident.getStatus().equals("Closed")) {
                count++;
            }
        }
        return count;
    }

    public int countHighSeverity() {
        int count = 0;
        for (SecurityIncident incident : incidents) {
            if (incident.requiresEscalation()) {
                count++;
            }
        }
        return count;
    }

    public static int severityRank(String severity) {
        return Arrays.asList(SEVERITIES).indexOf(severity);
    }

    // Resolution queue: a PriorityQueue puts the most urgent unresolved ticket first
    public List<SecurityIncident> getResolutionQueue() {
        PriorityQueue<SecurityIncident> queue = new PriorityQueue<>(
                Comparator.comparingInt((SecurityIncident i) -> -severityRank(i.getSeverity()))
                        .thenComparingInt(i -> -i.calculateRiskScore())
                        .thenComparingInt(SecurityIncident::getId));
        for (SecurityIncident incident : incidents) {
            if (incident.getStatus().equals("Open") || incident.getStatus().equals("Under Investigation")) {
                queue.add(incident);
            }
        }
        List<SecurityIncident> ordered = new ArrayList<>();
        while (!queue.isEmpty()) {
            ordered.add(queue.poll());
        }
        return ordered;
    }

    public void resolve(int id)
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        SecurityIncident incident = find(id);
        if (incident.getStatus().equals("Closed")) {
            throw new IncidentClosedException("This incident is closed and can no longer be changed.");
        }
        if (incident.getStatus().equals("Resolved")) {
            throw new InvalidInputException("This ticket is already resolved.");
        }
        incident.setStatus("Resolved");
        escalationQueue.remove(incident);
        saveRow(incident);
        saveQueue();
    }

    public SecurityIncident resolveNext()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        List<SecurityIncident> queue = getResolutionQueue();
        if (queue.isEmpty()) {
            return null;
        }
        SecurityIncident next = queue.get(0);
        resolve(next.getId());
        return next;
    }

    public String startNextTicket() {
        for (SecurityIncident incident : getResolutionQueue()) {
            if (incident.getStatus().equals("Open")) {
                incident.setStatus("Under Investigation");
                saveRow(incident);
                return "Ticket #" + incident.getId() + " is now under investigation.";
            }
        }
        return "No open tickets are waiting.";
    }

    // ---------- Helpers ----------
    private SecurityIncident create(String type, int id, String reporter, String description, String severity) {
        switch (type) {
            case "Malware":
                return new MalwareIncident(id, reporter, description, severity);
            case "Phishing":
                return new PhishingIncident(id, reporter, description, severity);
            default:
                return new UnauthorizedAccessIncident(id, reporter, description, severity);
        }
    }

    private void queueIfNeeded(SecurityIncident incident) {
        if (incident.requiresEscalation() && !escalationQueue.contains(incident)) {
            escalationQueue.add(incident);
        }
    }

    private String requireText(String value, String message) throws InvalidInputException {
        String text = value == null ? "" : value.trim();
        if (text.isEmpty()) {
            throw new InvalidInputException(message);
        }
        return text;
    }

    private void requireOneOf(String value, String[] allowed, String message) throws InvalidInputException {
        if (value == null || !Arrays.asList(allowed).contains(value)) {
            throw new InvalidInputException(message);
        }
    }

    // ---------- SQLite ----------
    private void loadFromDatabase() throws SQLException {
        HashMap<SecurityIncident, Integer> order = new HashMap<>();
        try (Statement st = connection.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, type, reporter, description, severity, status, "
                     + "queue_order FROM incidents ORDER BY id")) {
            while (rs.next()) {
                SecurityIncident incident = create(rs.getString("type"), rs.getInt("id"),
                        rs.getString("reporter"), rs.getString("description"), rs.getString("severity"));
                incident.setStatus(rs.getString("status"));
                incidents.add(incident);
                incidentMap.put(incident.getId(), incident);
                int position = rs.getInt("queue_order");
                if (!rs.wasNull()) {
                    order.put(incident, position);
                }
            }
        }
        List<SecurityIncident> queued = new ArrayList<>(order.keySet());
        queued.sort(Comparator.comparingInt((SecurityIncident i) -> order.get(i)));
        escalationQueue.addAll(queued);
    }

    private int insertRow(String type, String reporter, String description, String severity) {
        if (connection == null) {
            return nextId++;
        }
        String sql = "INSERT INTO incidents (type, reporter, description, severity, status) "
                + "VALUES (?, ?, ?, ?, 'Open')";
        try (PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, type);
            ps.setString(2, reporter);
            ps.setString(3, description);
            ps.setString(4, severity);
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                keys.next();
                return keys.getInt(1);
            }
        } catch (SQLException e) {
            throw new DatabaseException("Could not save the incident: " + e.getMessage(), e);
        }
    }

    private void saveRow(SecurityIncident incident) {
        if (connection == null) {
            return;
        }
        String sql = "UPDATE incidents SET reporter = ?, description = ?, severity = ?, status = ? WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, incident.getReporter());
            ps.setString(2, incident.getDescription());
            ps.setString(3, incident.getSeverity());
            ps.setString(4, incident.getStatus());
            ps.setInt(5, incident.getId());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Could not update the incident: " + e.getMessage(), e);
        }
    }

    private void deleteRow(int id) {
        if (connection == null) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement("DELETE FROM incidents WHERE id = ?")) {
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("Could not delete the incident: " + e.getMessage(), e);
        }
    }

    // Stores the escalation queue order so it survives a restart
    private void saveQueue() {
        if (connection == null) {
            return;
        }
        try {
            connection.setAutoCommit(false);
            try (Statement st = connection.createStatement()) {
                st.executeUpdate("UPDATE incidents SET queue_order = NULL");
            }
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE incidents SET queue_order = ? WHERE id = ?")) {
                int position = 1;
                for (SecurityIncident incident : escalationQueue) {
                    ps.setInt(1, position++);
                    ps.setInt(2, incident.getId());
                    ps.executeUpdate();
                }
            }
            connection.commit();
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException ignored) {
                // the original error is reported below
            }
            throw new DatabaseException("Could not save the escalation queue: " + e.getMessage(), e);
        } finally {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException ignored) {
                // connection already closed
            }
        }
    }
}

// ================= GUI: theme and custom components =================
final class Theme {
    static final Color BRAND = new Color(0x1F4E79);
    static final Color BG = new Color(0xE9EDF1);
    static final Color INK = new Color(0x1B2733);
    static final Color MUTED = new Color(0x5D6B79);
    static final Color LINE = new Color(0xCFD7DF);
    static final Color LOW = new Color(0x3A7D5C);
    static final Color MEDIUM = new Color(0xB7791F);
    static final Color HIGH = new Color(0xC05621);
    static final Color CRITICAL = new Color(0xB02A37);
    static final Font BASE = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    static final Font BOLD = BASE.deriveFont(Font.BOLD);

    static Color severity(String s) {
        switch (s) {
            case "Low": return LOW;
            case "High": return HIGH;
            case "Critical": return CRITICAL;
            default: return MEDIUM;
        }
    }

    static Color status(String s) {
        switch (s) {
            case "Under Investigation": return HIGH;
            case "Resolved": return LOW;
            case "Closed": return MUTED;
            default: return BRAND;
        }
    }

    static Color blend(Color a, Color b, float t) {
        return new Color(
                (int) (a.getRed() + (b.getRed() - a.getRed()) * t),
                (int) (a.getGreen() + (b.getGreen() - a.getGreen()) * t),
                (int) (a.getBlue() + (b.getBlue() - a.getBlue()) * t));
    }

    static void smooth(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
    }
}

// Table that shows a friendly message when it has no rows
class EmptyTable extends JTable {
    private final String message;

    EmptyTable(DefaultTableModel model, String message) {
        super(model);
        this.message = message;
        setFillsViewportHeight(true);
    }

    @Override
    protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        if (getRowCount() == 0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.smooth(g);
            g.setFont(Theme.BASE);
            g.setColor(Theme.MUTED);
            FontMetrics fm = g.getFontMetrics();
            g.drawString(message, (getWidth() - fm.stringWidth(message)) / 2, 60);
            g.dispose();
        }
    }
}

// White rounded panel used for the form and the table
class RoundPanel extends JPanel {
    RoundPanel(LayoutManager layout) {
        super(layout);
        setOpaque(false);
    }

    @Override
    protected void paintComponent(Graphics g0) {
        Graphics2D g = (Graphics2D) g0.create();
        Theme.smooth(g);
        g.setColor(Color.WHITE);
        g.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
        g.setColor(Theme.LINE);
        g.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
        g.dispose();
    }
}

// Rounded button that darkens when the mouse hovers over it
class RoundButton extends JButton {
    private final Color base;
    private boolean hover;

    RoundButton(String text, Color base, Color textColor) {
        super(text);
        this.base = base;
        setForeground(textColor);
        setFont(Theme.BOLD);
        setContentAreaFilled(false);
        setFocusPainted(false);
        setBorderPainted(false);
        setOpaque(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder(8, 14, 8, 14));
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                hover = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hover = false;
                repaint();
            }
        });
    }

    @Override
    protected void paintComponent(Graphics g0) {
        Graphics2D g = (Graphics2D) g0.create();
        Theme.smooth(g);
        g.setColor(hover ? Theme.blend(base, Color.BLACK, 0.15f) : base);
        g.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
        g.dispose();
        super.paintComponent(g0);
    }
}

// Dashboard card whose number counts up or down smoothly (animation)
class StatCard extends JPanel {
    private final String title;
    private final Color accent;
    private int shown = 0;
    private int target = 0;
    private Timer timer;

    StatCard(String title, Color accent) {
        this.title = title;
        this.accent = accent;
        setOpaque(false);
        setPreferredSize(new Dimension(160, 88));
    }

    void setValue(int value) {
        if (value == target) {
            return;
        }
        target = value;
        if (timer != null) {
            timer.stop();
        }
        timer = new Timer(20, e -> {
            int diff = target - shown;
            if (diff == 0) {
                timer.stop();
                return;
            }
            shown += diff > 0 ? Math.max(1, diff / 6) : Math.min(-1, diff / 6);
            repaint();
        });
        timer.start();
    }

    @Override
    protected void paintComponent(Graphics g0) {
        Graphics2D g = (Graphics2D) g0.create();
        Theme.smooth(g);
        int w = getWidth();
        int h = getHeight();
        g.setColor(Color.WHITE);
        g.fillRoundRect(0, 0, w - 1, h - 1, 16, 16);
        g.setColor(Theme.LINE);
        g.drawRoundRect(0, 0, w - 1, h - 1, 16, 16);
        g.setColor(accent);
        g.fillRoundRect(0, 12, 6, h - 25, 6, 6);
        g.setFont(Theme.BASE);
        g.setColor(Theme.MUTED);
        g.drawString(title, 20, 28);
        g.setFont(Theme.BASE.deriveFont(Font.BOLD, 30f));
        g.setColor(Theme.INK);
        g.drawString(String.valueOf(shown), 20, h - 18);
        g.dispose();
    }
}

// ================= GUI: main window =================
interface UiAction {
    void run() throws Exception;
}

class IncidentApp extends JFrame {
    private static final String[] COLUMNS = {"ID", "Type", "Reporter", "Description", "Severity", "Status", "Risk"};

    private final IncidentManager manager;
    private final AccountManager accounts;
    private final UserAccount account;
    private final boolean admin;
    private final DefaultTableModel model = new DefaultTableModel(COLUMNS, 0) {
        @Override
        public boolean isCellEditable(int row, int col) { return false; }

        @Override
        public Class<?> getColumnClass(int col) {
            return (col == 0 || col == 6) ? Integer.class : String.class;
        }
    };
    private final JTable table = new EmptyTable(model, "No tickets to show.");

    private final DefaultTableModel queueModel = new DefaultTableModel(
            new String[]{"Position", "Ticket #", "Type", "Reporter", "Severity", "Status", "Risk"}, 0) {
        @Override
        public boolean isCellEditable(int row, int col) { return false; }

        @Override
        public Class<?> getColumnClass(int col) {
            return (col == 0 || col == 1 || col == 6) ? Integer.class : String.class;
        }
    };
    private final JTable queueTable = new EmptyTable(queueModel, "No tickets are waiting to be resolved.");
    private final JTabbedPane tabs = new JTabbedPane();

    private final DefaultTableModel usersModel = new DefaultTableModel(
            new String[]{"Username", "Full name", "Role"}, 0) {
        @Override
        public boolean isCellEditable(int row, int col) { return false; }
    };
    private final JTable usersTable = new EmptyTable(usersModel, "No accounts yet.");

    private static final String[] SORTS = {
        "Ticket number", "Severity: Critical and High first", "Severity: Low and Medium first",
        "Ticket status", "Risk score (highest first)"};
    private final JComboBox<String> sortBox = new JComboBox<>(SORTS);
    private final JCheckBox reverseBox = new JCheckBox("Reverse order");
    private final JComboBox<String> filterBox = new JComboBox<>(
            new String[]{"All cases", "Pending cases", "Resolved or closed cases"});

    // The ticket currently loaded in the Ticket Input form (null = creating a new ticket)
    private Integer editingId = null;
    private final JLabel formHeading = new JLabel("New ticket");

    private final StatCard totalCard = new StatCard("Total incidents", Theme.BRAND);
    private final StatCard activeCard = new StatCard("Active (not closed)", new Color(0x2F7AB8));
    private final StatCard closedCard = new StatCard("Closed", Theme.MUTED);
    private final StatCard highCard = new StatCard("High / Critical", Theme.CRITICAL);
    private final StatCard queueCard = new StatCard("In escalation queue", Theme.HIGH);

    private final JComboBox<String> typeBox = new JComboBox<>(IncidentManager.TYPES);
    private final JComboBox<String> severityBox = new JComboBox<>(IncidentManager.SEVERITIES);
    private final JComboBox<String> statusBox = new JComboBox<>(IncidentManager.STATUSES);
    private final JTextField reporterField = new JTextField();
    private final JTextField searchField = new JTextField(6);
    private final JTextArea descArea = new JTextArea(5, 20);
    private final JCheckBox highOnly = new JCheckBox("High severity only");

    // Animation state: success message fade and row highlight flash
    private final JLabel toast = new JLabel(" ");
    private Timer toastTimer;
    private int toastStep;
    private Integer flashId;
    private float flashAlpha = 0f;
    private Timer flashTimer;

    public IncidentApp(IncidentManager manager, AccountManager accounts, UserAccount account) {
        super("Cybersecurity Incident System - " + (account.getRole() == Role.ADMIN ? "Admin" : "User") + " view");
        this.manager = manager;
        this.accounts = accounts;
        this.account = account;
        this.admin = account.getRole() == Role.ADMIN;
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        getContentPane().setBackground(Theme.BG);
        setLayout(new BorderLayout(12, 12));
        ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(14, 14, 10, 14));

        JPanel top = new JPanel(new BorderLayout(0, 12));
        top.setOpaque(false);
        top.add(buildHeader(), BorderLayout.NORTH);
        top.add(buildDashboard(), BorderLayout.CENTER);
        add(top, BorderLayout.NORTH);

        JPanel inputTab = new JPanel(new GridBagLayout());
        inputTab.setOpaque(false);
        inputTab.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        GridBagConstraints ic = new GridBagConstraints();
        ic.weightx = 1;
        ic.weighty = 1;
        ic.fill = GridBagConstraints.VERTICAL;
        ic.anchor = GridBagConstraints.NORTH;
        inputTab.add(buildForm(), ic);

        JPanel casesTab = new JPanel(new BorderLayout());
        casesTab.setOpaque(false);
        casesTab.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
        casesTab.add(buildTablePanel(), BorderLayout.CENTER);

        tabs.setFont(Theme.BOLD);
        tabs.addTab("Ticket Input", inputTab);
        tabs.addTab("All Cases (0)", casesTab);
        if (admin) {
            JPanel queueTab = new JPanel(new BorderLayout());
            queueTab.setOpaque(false);
            queueTab.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
            queueTab.add(buildQueuePanel(), BorderLayout.CENTER);
            tabs.addTab("Resolution Queue (0)", queueTab);

            JPanel usersTab = new JPanel(new BorderLayout());
            usersTab.setOpaque(false);
            usersTab.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
            usersTab.add(buildUsersPanel(), BorderLayout.CENTER);
            tabs.addTab("Users (0)", usersTab);
        }
        add(tabs, BorderLayout.CENTER);

        toast.setFont(Theme.BOLD);
        toast.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        JLabel dbInfo = new JLabel(manager.getStorageInfo());
        dbInfo.setFont(Theme.BASE);
        dbInfo.setForeground(Theme.MUTED);
        JPanel status = new JPanel(new BorderLayout());
        status.setOpaque(false);
        status.add(toast, BorderLayout.CENTER);
        status.add(dbInfo, BorderLayout.EAST);
        add(status, BorderLayout.SOUTH);

        clearForm();
        setSize(1180, 740);
        setMinimumSize(new Dimension(980, 560));
        setLocationRelativeTo(null);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                manager.close();
            }
        });
        refresh();
        String warning = manager.takeStartupWarning();
        if (warning != null) {
            SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                    warning, "Database not available", JOptionPane.WARNING_MESSAGE));
        }
    }

    // ---------- Layout ----------
    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g0) {
                Graphics2D g = (Graphics2D) g0.create();
                Theme.smooth(g);
                g.setPaint(new GradientPaint(0, 0, Theme.BRAND, getWidth(), 0, new Color(0x2F7AB8)));
                g.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g.dispose();
            }
        };
        header.setOpaque(false);

        JLabel title = new JLabel("Cybersecurity Incident System");
        title.setFont(Theme.BASE.deriveFont(Font.BOLD, 22f));
        title.setForeground(Color.WHITE);
        JLabel subtitle = new JLabel(admin ? "Report, track and escalate security incidents"
                : "Report security incidents and track their status");
        subtitle.setFont(Theme.BASE);
        subtitle.setForeground(new Color(0xD6E6F5));

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setBorder(BorderFactory.createEmptyBorder(14, 20, 14, 20));
        text.add(title);
        text.add(subtitle);
        header.add(text, BorderLayout.CENTER);

        JLabel who = new JLabel("Signed in as: " + account.getFullName() + " (" + (admin ? "Admin" : "User") + ")");
        who.setFont(Theme.BOLD);
        who.setForeground(Color.WHITE);
        RoundButton logoutBtn = new RoundButton("Log out", Color.WHITE, Theme.BRAND);
        logoutBtn.addActionListener(e -> logout());
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 12, 0));
        right.setOpaque(false);
        right.setBorder(BorderFactory.createEmptyBorder(22, 0, 0, 14));
        right.add(who);
        right.add(logoutBtn);
        header.add(right, BorderLayout.EAST);
        return header;
    }

    private JPanel buildDashboard() {
        JPanel panel = new JPanel(new GridLayout(1, admin ? 5 : 3, 12, 0));
        panel.setOpaque(false);
        panel.add(totalCard);
        panel.add(activeCard);
        panel.add(closedCard);
        if (admin) {
            panel.add(highCard);
            panel.add(queueCard);
        }
        return panel;
    }

    private static Border inputBorder() {
        return BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.LINE),
                BorderFactory.createEmptyBorder(5, 8, 5, 8));
    }

    private JPanel buildForm() {
        RoundPanel panel = new RoundPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(16, 18, 16, 18));
        panel.setPreferredSize(new Dimension(640, 380));

        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setFont(Theme.BASE);
        descArea.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8));
        reporterField.setFont(Theme.BASE);
        reporterField.setBorder(inputBorder());
        reporterField.setEditable(admin);
        if (!admin) {
            reporterField.setBackground(new Color(0xF3F5F7));
        }
        JScrollPane descScroll = new JScrollPane(descArea);
        descScroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        for (JComboBox<String> box : Arrays.asList(typeBox, severityBox, statusBox)) {
            box.setFont(Theme.BASE);
            box.setBackground(Color.WHITE);
        }

        RoundButton addBtn = new RoundButton("Add ticket", Theme.BRAND, Color.WHITE);
        RoundButton saveBtn = new RoundButton("Save changes", Theme.LOW, Color.WHITE);
        RoundButton clearBtn = new RoundButton("Clear form", new Color(0xEEF1F4), Theme.INK);
        addBtn.addActionListener(e -> perform(this::addIncident));
        saveBtn.addActionListener(e -> perform(this::updateIncident));
        clearBtn.addActionListener(e -> clearForm());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttons.setOpaque(false);
        buttons.add(addBtn);
        if (admin) {
            buttons.add(saveBtn);
        }
        buttons.add(clearBtn);

        formHeading.setFont(Theme.BASE.deriveFont(Font.BOLD, 18f));
        formHeading.setForeground(Theme.BRAND);

        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;
        g.insets = new Insets(3, 6, 3, 6);

        place(panel, g, formHeading, 0, 0, 2);
        place(panel, g, label("Incident type"), 0, 1, 1);
        place(panel, g, label("Reporter name"), 1, 1, 1);
        place(panel, g, typeBox, 0, 2, 1);
        place(panel, g, reporterField, 1, 2, 1);
        place(panel, g, label("Severity"), 0, 3, admin ? 1 : 2);
        place(panel, g, severityBox, 0, 4, admin ? 1 : 2);
        if (admin) {
            place(panel, g, label("Status (when editing)"), 1, 3, 1);
            place(panel, g, statusBox, 1, 4, 1);
        }
        place(panel, g, label("Description"), 0, 5, 2);
        g.weighty = 1;
        g.fill = GridBagConstraints.BOTH;
        place(panel, g, descScroll, 0, 6, 2);
        g.weighty = 0;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.insets = new Insets(12, 6, 3, 6);
        place(panel, g, buttons, 0, 7, 2);
        return panel;
    }

    private JLabel label(String text) {
        JLabel label = new JLabel(text);
        label.setFont(Theme.BOLD.deriveFont(12f));
        label.setForeground(Theme.MUTED);
        return label;
    }

    private void place(JPanel panel, GridBagConstraints g, Component c, int x, int y, int width) {
        g.gridx = x;
        g.gridy = y;
        g.gridwidth = width;
        panel.add(c, g);
    }

    private JPanel buildTablePanel() {
        RoundPanel panel = new RoundPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        RoundButton searchBtn = new RoundButton("Search", Theme.BRAND, Color.WHITE);
        RoundButton escalateBtn = new RoundButton("Process next escalation", Theme.HIGH, Color.WHITE);
        RoundButton viewBtn = new RoundButton("View details", new Color(0xE3ECF5), Theme.BRAND);
        RoundButton editBtn = new RoundButton("Edit selected", Theme.LOW, Color.WHITE);
        RoundButton deleteBtn = new RoundButton("Delete", Theme.CRITICAL, Color.WHITE);
        searchBtn.addActionListener(e -> perform(this::searchIncident));
        escalateBtn.addActionListener(e -> perform(this::escalateNext));
        viewBtn.addActionListener(e -> perform(this::viewIncident));
        editBtn.addActionListener(e -> perform(this::editSelected));
        deleteBtn.addActionListener(e -> perform(this::deleteIncident));

        highOnly.setOpaque(false);
        highOnly.setFont(Theme.BASE);
        highOnly.addActionListener(e -> refresh());
        searchField.setFont(Theme.BASE);
        searchField.setBorder(inputBorder());
        filterBox.setFont(Theme.BASE);
        filterBox.setBackground(Color.WHITE);
        filterBox.addActionListener(e -> refresh());
        sortBox.setFont(Theme.BASE);
        sortBox.setBackground(Color.WHITE);
        sortBox.addActionListener(e -> refresh());
        reverseBox.setOpaque(false);
        reverseBox.setFont(Theme.BASE);
        reverseBox.addActionListener(e -> refresh());

        JPanel searchBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        searchBar.setOpaque(false);
        searchBar.add(new JLabel("Incident ID:"));
        searchBar.add(searchField);
        searchBar.add(searchBtn);
        searchBar.add(new JLabel("Show:"));
        searchBar.add(filterBox);
        searchBar.add(highOnly);

        JPanel sortBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        sortBar.setOpaque(false);
        sortBar.add(new JLabel("Sort by:"));
        sortBar.add(sortBox);
        sortBar.add(reverseBox);

        JPanel bars = new JPanel(new GridLayout(2, 1, 0, 8));
        bars.setOpaque(false);
        bars.add(searchBar);
        bars.add(sortBar);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setOpaque(false);
        actions.add(viewBtn);
        if (admin) {
            actions.add(editBtn);
            actions.add(deleteBtn);
            actions.add(escalateBtn);
        }

        styleTable(table, 0);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
                    perform(() -> viewIncident()); // double-click opens the details
                }
            }
        });
        searchField.addActionListener(e -> perform(this::searchIncident));
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(3).setPreferredWidth(280);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        scroll.getViewport().setBackground(Color.WHITE);

        panel.add(bars, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        panel.add(actions, BorderLayout.SOUTH);
        return panel;
    }

    private void styleTable(JTable t, int idCol) {
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setFont(Theme.BASE);
        t.setRowHeight(30);
        t.setShowVerticalLines(false);
        t.setGridColor(Theme.LINE);
        t.setIntercellSpacing(new Dimension(0, 1));

        RowRenderer renderer = new RowRenderer(idCol);
        t.setDefaultRenderer(Object.class, renderer);
        t.setDefaultRenderer(String.class, renderer);
        t.setDefaultRenderer(Integer.class, renderer);

        t.getTableHeader().setReorderingAllowed(false);
        t.getTableHeader().setPreferredSize(new Dimension(0, 34));
        t.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable tb, Object v, boolean sel, boolean f, int r, int c) {
                super.getTableCellRendererComponent(tb, v, false, false, r, c);
                setBackground(Theme.BRAND);
                setForeground(Color.WHITE);
                setFont(Theme.BOLD);
                setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                setHorizontalAlignment(c == 0 || c == idCol || c >= 4 ? CENTER : LEFT);
                return this;
            }
        });
    }

    // Colours rows: stripes, coloured severity/status text and the highlight flash
    private class RowRenderer extends DefaultTableCellRenderer {
        private final int idCol;
        private Color pill;

        RowRenderer(int idCol) {
            this.idCol = idCol;
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            super.getTableCellRendererComponent(t, value, false, false, row, col);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            setHorizontalAlignment(col == 0 || col == idCol || col >= 4 ? CENTER : LEFT);

            Color bg = row % 2 == 0 ? Color.WHITE : new Color(0xF5F8FB);
            if (flashAlpha > 0f && t.getValueAt(row, idCol).equals(flashId)) {
                bg = Theme.blend(bg, new Color(0xFFE08A), flashAlpha);
            }
            if (sel) {
                bg = new Color(0xD6E6F5);
            }
            setBackground(bg);
            setForeground(Theme.INK);
            setFont(Theme.BASE);
            pill = null;
            if (col == 4) {
                pill = Theme.severity(String.valueOf(value));
            } else if (col == 5) {
                pill = Theme.status(String.valueOf(value));
            }
            if (pill != null) {
                setFont(Theme.BOLD.deriveFont(12f));
            }
            return this;
        }

        // Severity and status are drawn as rounded coloured badges
        @Override
        protected void paintComponent(Graphics g0) {
            if (pill == null) {
                super.paintComponent(g0);
                return;
            }
            Graphics2D g = (Graphics2D) g0.create();
            Theme.smooth(g);
            g.setColor(getBackground());
            g.fillRect(0, 0, getWidth(), getHeight());
            g.setFont(getFont());
            FontMetrics fm = g.getFontMetrics();
            String text = getText();
            int w = fm.stringWidth(text) + 22;
            int h = fm.getHeight() + 4;
            int x = (getWidth() - w) / 2;
            int y = (getHeight() - h) / 2;
            g.setColor(pill);
            g.fillRoundRect(x, y, w, h, h, h);
            g.setColor(Color.WHITE);
            g.drawString(text, x + 11, y + 2 + fm.getAscent());
            g.dispose();
        }
    }

    // ---------- Button actions ----------
    private void addIncident() throws InvalidInputException {
        if (editingId != null) {
            throw new InvalidInputException("You are editing ticket #" + editingId
                    + ". Click \"Clear form\" to start a new ticket.");
        }
        SecurityIncident incident = manager.report((String) typeBox.getSelectedItem(),
                admin ? reporterField.getText() : account.getFullName(),
                descArea.getText(), (String) severityBox.getSelectedItem());
        clearForm();
        flashRow(incident.getId());
        toast("Incident #" + incident.getId() + " reported successfully.");
    }

    private void requireAdmin() throws InvalidInputException {
        if (!admin) {
            throw new InvalidInputException("Only an admin can do this. Your account can view and create tickets.");
        }
    }

    private void logout() {
        setVisible(false);
        UserAccount next = LoginDialog.ask(null, accounts);
        dispose();
        if (next == null) {
            manager.close();
            System.exit(0);
        }
        new IncidentApp(manager, accounts, next).setVisible(true);
    }

    private void viewIncident() throws InvalidInputException, IncidentNotFoundException {
        int id = requireSelected();
        showDetails("Incident #" + id, manager.find(id).describe(false));
    }

    private void updateIncident()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        requireAdmin();
        if (editingId == null) {
            throw new InvalidInputException(
                    "Select a ticket in the All Cases tab and click \"Edit selected\" first.");
        }
        int id = editingId;
        manager.update(id, reporterField.getText(), descArea.getText(),
                (String) severityBox.getSelectedItem(), (String) statusBox.getSelectedItem());
        clearForm();
        flashRow(id);
        toast("Ticket #" + id + " has been updated.");
        tabs.setSelectedIndex(1);
    }

    private void deleteIncident() throws InvalidInputException, IncidentNotFoundException {
        requireAdmin();
        int id = requireSelected();
        SecurityIncident incident = manager.find(id);
        int answer = JOptionPane.showConfirmDialog(this,
                "Delete this incident permanently?\n\n" + incident.describe(true),
                "Confirm delete", JOptionPane.YES_NO_OPTION);
        if (answer == JOptionPane.YES_OPTION) {
            manager.delete(id);
            if (editingId != null && editingId == id) {
                clearForm();
            }
            toast("Incident #" + id + " has been deleted.");
        }
    }

    private void editSelected() throws InvalidInputException, IncidentNotFoundException {
        requireAdmin();
        int id = requireSelected();
        loadForm(id);
        tabs.setSelectedIndex(0);
    }

    private void searchIncident() throws InvalidInputException, IncidentNotFoundException {
        int id;
        try {
            id = Integer.parseInt(searchField.getText().trim());
        } catch (NumberFormatException e) {
            throw new InvalidInputException("Please enter a valid whole number.");
        }
        SecurityIncident incident = manager.find(id);
        selectRowById(id);
        showDetails("Incident #" + id, incident.describe(false));
    }

    private void escalateNext() throws InvalidInputException {
        requireAdmin();
        showDetails("Escalation", manager.processNextEscalation());
    }

    // ---------- Resolution queue tab ----------
    private JPanel buildQueuePanel() {
        RoundPanel panel = new RoundPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel info = new JLabel("Tickets waiting to be resolved, most urgent first "
                + "(severity, then risk score, then ticket number). Position 1 is next.");
        info.setFont(Theme.BASE);
        info.setForeground(Theme.MUTED);

        RoundButton startBtn = new RoundButton("Start next ticket", Theme.BRAND, Color.WHITE);
        RoundButton resolveNextBtn = new RoundButton("Resolve next ticket", Theme.LOW, Color.WHITE);
        RoundButton resolveSelBtn = new RoundButton("Resolve selected", new Color(0xE3ECF5), Theme.BRAND);
        startBtn.addActionListener(e -> perform(this::startNext));
        resolveNextBtn.addActionListener(e -> perform(this::resolveNext));
        resolveSelBtn.addActionListener(e -> perform(this::resolveSelected));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttons.setOpaque(false);
        buttons.add(startBtn);
        buttons.add(resolveNextBtn);
        buttons.add(resolveSelBtn);

        JPanel north = new JPanel(new GridLayout(2, 1, 0, 8));
        north.setOpaque(false);
        north.add(info);
        north.add(buttons);

        styleTable(queueTable, 1);
        queueTable.getColumnModel().getColumn(0).setPreferredWidth(70);
        queueTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        queueTable.getColumnModel().getColumn(3).setPreferredWidth(200);
        JScrollPane scroll = new JScrollPane(queueTable);
        scroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        scroll.getViewport().setBackground(Color.WHITE);

        panel.add(north, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private void startNext() throws InvalidInputException {
        requireAdmin();
        toast(manager.startNextTicket());
    }

    private void resolveNext()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        requireAdmin();
        SecurityIncident done = manager.resolveNext();
        if (done == null) {
            throw new InvalidInputException("No tickets are waiting to be resolved.");
        }
        flashRow(done.getId());
        toast("Ticket #" + done.getId() + " has been resolved.");
    }

    private void resolveSelected()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        requireAdmin();
        Integer id = selectedQueueId();
        if (id == null) {
            throw new InvalidInputException("Select a ticket in the queue first.");
        }
        manager.resolve(id);
        flashRow(id);
        toast("Ticket #" + id + " has been resolved.");
    }

    // ---------- Users tab (admin only) ----------
    private JPanel buildUsersPanel() {
        RoundPanel panel = new RoundPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JLabel info = new JLabel("Registered accounts. Passwords are stored as salted hashes, never as plain text.");
        info.setFont(Theme.BASE);
        info.setForeground(Theme.MUTED);
        RoundButton removeBtn = new RoundButton("Remove selected account", Theme.CRITICAL, Color.WHITE);
        removeBtn.addActionListener(e -> perform(this::removeUser));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttons.setOpaque(false);
        buttons.add(removeBtn);
        JPanel north = new JPanel(new GridLayout(2, 1, 0, 8));
        north.setOpaque(false);
        north.add(info);
        north.add(buttons);

        styleTable(usersTable, 0);
        JScrollPane scroll = new JScrollPane(usersTable);
        scroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        scroll.getViewport().setBackground(Color.WHITE);
        panel.add(north, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private void removeUser() throws InvalidInputException {
        requireAdmin();
        int row = usersTable.getSelectedRow();
        if (row < 0) {
            throw new InvalidInputException("Select an account in the table first.");
        }
        String username = (String) usersTable.getValueAt(row, 0);
        int answer = JOptionPane.showConfirmDialog(this,
                "Remove the account \"" + username + "\"? Their tickets are kept.",
                "Confirm remove", JOptionPane.YES_NO_OPTION);
        if (answer == JOptionPane.YES_OPTION) {
            accounts.remove(username);
            toast("Account " + username + " has been removed.");
        }
    }

    private void refreshUsersTab() {
        if (!admin) {
            return;
        }
        usersModel.setRowCount(0);
        for (UserAccount u : accounts.all()) {
            usersModel.addRow(new Object[]{u.getUsername(), u.getFullName(),
                    u.getRole() == Role.ADMIN ? "Admin" : "User"});
        }
        tabs.setTitleAt(3, "Users (" + usersModel.getRowCount() + ")");
    }

    private Integer selectedQueueId() {
        int row = queueTable.getSelectedRow();
        return row < 0 ? null : (Integer) queueTable.getValueAt(row, 1);
    }

    private void refreshQueueTab() {
        if (!admin) {
            return;
        }
        Integer keep = selectedQueueId();
        queueModel.setRowCount(0);
        int position = 1;
        for (SecurityIncident i : manager.getResolutionQueue()) {
            queueModel.addRow(new Object[]{position++, i.getId(), i.getIncidentType(), i.getReporter(),
                    i.getSeverity(), i.getStatus(), i.calculateRiskScore()});
        }
        tabs.setTitleAt(2, "Resolution Queue (" + queueModel.getRowCount() + ")");
        if (keep != null) {
            for (int row = 0; row < queueTable.getRowCount(); row++) {
                if ((Integer) queueTable.getValueAt(row, 1) == keep.intValue()) {
                    queueTable.setRowSelectionInterval(row, row);
                    break;
                }
            }
        }
    }

    // ---------- Sorter for the incidents table ----------
    private Comparator<SecurityIncident> currentSort() {
        Comparator<SecurityIncident> byId = Comparator.comparingInt(SecurityIncident::getId);
        Comparator<SecurityIncident> sort;
        switch (sortBox.getSelectedIndex()) {
            case 1: // Critical and High first
                sort = Comparator.comparingInt((SecurityIncident i) -> -IncidentManager.severityRank(i.getSeverity()))
                        .thenComparing(byId);
                break;
            case 2: // Low and Medium first
                sort = Comparator.comparingInt((SecurityIncident i) -> IncidentManager.severityRank(i.getSeverity()))
                        .thenComparing(byId);
                break;
            case 3: // ticket status in workflow order
                sort = Comparator.comparingInt((SecurityIncident i) ->
                        Arrays.asList(IncidentManager.STATUSES).indexOf(i.getStatus())).thenComparing(byId);
                break;
            case 4: // risk score, highest first
                sort = Comparator.comparingInt((SecurityIncident i) -> -i.calculateRiskScore()).thenComparing(byId);
                break;
            default: // ticket number
                sort = byId;
                break;
        }
        return reverseBox.isSelected() ? sort.reversed() : sort;
    }

    // ---------- Error handling: pop-ups instead of crashes ----------
    private void perform(UiAction action) {
        try {
            action.run();
        } catch (InvalidInputException | IncidentNotFoundException | IncidentClosedException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        } catch (DatabaseException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Database error", JOptionPane.ERROR_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Unexpected error: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        } finally {
            refresh(); // table and dashboard always update after every action
        }
    }

    // ---------- Animations ----------
    private void flashRow(int id) {
        flashId = id;
        flashAlpha = 1f;
        if (flashTimer != null) {
            flashTimer.stop();
        }
        flashTimer = new Timer(40, e -> {
            flashAlpha -= 0.05f;
            if (flashAlpha <= 0f) {
                flashAlpha = 0f;
                flashTimer.stop();
            }
            table.repaint();
            queueTable.repaint();
        });
        flashTimer.start();
    }

    private void toast(String text) {
        toast.setText(text);
        toast.setForeground(Theme.LOW);
        if (toastTimer != null) {
            toastTimer.stop();
        }
        toastStep = 0;
        toastTimer = new Timer(50, e -> {
            toastStep++;
            if (toastStep < 50) {
                return; // keep the message visible for about 2.5 seconds
            }
            float t = (toastStep - 50) / 12f;
            if (t >= 1f) {
                toast.setText(" ");
                toastTimer.stop();
            } else {
                toast.setForeground(Theme.blend(Theme.LOW, Theme.BG, t));
            }
        });
        toastTimer.start();
    }

    // ---------- Helpers ----------
    private void refresh() {
        Integer keep = selectedId();
        model.setRowCount(0);
        List<SecurityIncident> sorted = manager.getIncidents();
        sorted.sort(currentSort());
        for (SecurityIncident i : sorted) {
            if (highOnly.isSelected() && !i.requiresEscalation()) {
                continue;
            }
            boolean pending = i.getStatus().equals("Open") || i.getStatus().equals("Under Investigation");
            if (filterBox.getSelectedIndex() == 1 && !pending) {
                continue;
            }
            if (filterBox.getSelectedIndex() == 2 && pending) {
                continue;
            }
            model.addRow(new Object[]{i.getId(), i.getIncidentType(), i.getReporter(),
                    i.getDescription(), i.getSeverity(), i.getStatus(), i.calculateRiskScore()});
        }
        totalCard.setValue(manager.getTotal());
        activeCard.setValue(manager.countActive());
        closedCard.setValue(manager.getTotal() - manager.countActive());
        highCard.setValue(manager.countHighSeverity());
        queueCard.setValue(manager.getQueueSize());
        refreshQueueTab();
        refreshUsersTab();
        tabs.setTitleAt(1, "All Cases (" + manager.getTotal() + ")");
        if (keep != null) {
            selectRowById(keep);
        }
    }

    private Integer selectedId() {
        int row = table.getSelectedRow();
        return row < 0 ? null : (Integer) table.getValueAt(row, 0);
    }

    private int requireSelected() throws InvalidInputException {
        Integer id = selectedId();
        if (id == null) {
            throw new InvalidInputException("Select an incident in the table first.");
        }
        return id;
    }

    private void selectRowById(int id) {
        for (int row = 0; row < table.getRowCount(); row++) {
            if ((Integer) table.getValueAt(row, 0) == id) {
                table.setRowSelectionInterval(row, row);
                return;
            }
        }
    }

    private void loadForm(int id) throws IncidentNotFoundException {
        SecurityIncident i = manager.find(id);
        typeBox.setSelectedItem(i.getIncidentType());
        reporterField.setText(i.getReporter());
        descArea.setText(i.getDescription());
        severityBox.setSelectedItem(i.getSeverity());
        statusBox.setSelectedItem(i.getStatus());
        typeBox.setEnabled(false);
        statusBox.setEnabled(true);
        editingId = id;
        formHeading.setText("Editing ticket #" + id);
    }

    private void clearForm() {
        editingId = null;
        reporterField.setText(admin ? "" : account.getFullName());
        descArea.setText("");
        typeBox.setSelectedIndex(0);
        severityBox.setSelectedItem("Medium");
        statusBox.setSelectedItem("Open");
        typeBox.setEnabled(true);
        statusBox.setEnabled(false);
        formHeading.setText("New ticket");
    }

    private void showDetails(String title, String text) {
        JTextArea area = new JTextArea(text, 11, 42);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        JOptionPane.showMessageDialog(this, new JScrollPane(area), title, JOptionPane.INFORMATION_MESSAGE);
    }
}
