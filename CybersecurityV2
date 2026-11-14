import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

public class Cybersecurity {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new IncidentApp().setVisible(true));
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

// ================= Data manager (collections + validation) =================
class IncidentManager {
    public static final String[] TYPES = {"Malware", "Phishing", "Unauthorized Access"};
    public static final String[] SEVERITIES = {"Low", "Medium", "High", "Critical"};
    public static final String[] STATUSES = {"Open", "Under Investigation", "Resolved", "Closed"};

    private final ArrayList<SecurityIncident> incidents = new ArrayList<>();
    private final HashMap<Integer, SecurityIncident> incidentMap = new HashMap<>();
    private final Queue<SecurityIncident> escalationQueue = new LinkedList<>();
    private int nextId = 1;

    // Create
    public SecurityIncident report(String type, String reporter, String description, String severity)
            throws InvalidInputException {
        requireOneOf(type, TYPES, "Invalid incident type.");
        reporter = requireText(reporter, "Reporter name cannot be empty.");
        description = requireText(description, "Incident description cannot be empty.");
        requireOneOf(severity, SEVERITIES, "Invalid severity choice.");

        SecurityIncident incident;
        switch (type) {
            case "Malware":
                incident = new MalwareIncident(nextId, reporter, description, severity);
                break;
            case "Phishing":
                incident = new PhishingIncident(nextId, reporter, description, severity);
                break;
            default:
                incident = new UnauthorizedAccessIncident(nextId, reporter, description, severity);
                break;
        }
        nextId++;
        incidents.add(incident);
        incidentMap.put(incident.getId(), incident);
        queueIfNeeded(incident);
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

        if (status.equals("Closed")) {
            escalationQueue.remove(incident);
        } else {
            queueIfNeeded(incident);
        }
    }

    // Delete
    public void delete(int id) throws IncidentNotFoundException {
        SecurityIncident incident = find(id);
        incidents.remove(incident);
        incidentMap.remove(id);
        escalationQueue.remove(incident);
    }

    public String processNextEscalation() {
        SecurityIncident incident;
        while ((incident = escalationQueue.poll()) != null) {
            if (!incident.getStatus().equals("Closed") && incident.requiresEscalation()) {
                String details = incident.describe();
                boolean changed = incident.getStatus().equals("Open");
                if (changed) {
                    incident.setStatus("Under Investigation");
                }
                return "Escalating next incident for review:\n\n" + details
                        + (changed ? "\n\nStatus changed to Under Investigation." : "")
                        + "\n\nIncidents still waiting in queue: " + escalationQueue.size();
            }
        }
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

    private final IncidentManager manager = new IncidentManager();
    private final DefaultTableModel model = new DefaultTableModel(COLUMNS, 0) {
        @Override
        public boolean isCellEditable(int row, int col) { return false; }

        @Override
        public Class<?> getColumnClass(int col) {
            return (col == 0 || col == 6) ? Integer.class : String.class;
        }
    };
    private final JTable table = new JTable(model);

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

    public IncidentApp() {
        super("Cybersecurity Incident System");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        getContentPane().setBackground(Theme.BG);
        setLayout(new BorderLayout(12, 12));
        ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(14, 14, 10, 14));

        JPanel top = new JPanel(new BorderLayout(0, 12));
        top.setOpaque(false);
        top.add(buildHeader(), BorderLayout.NORTH);
        top.add(buildDashboard(), BorderLayout.CENTER);
        add(top, BorderLayout.NORTH);
        add(buildForm(), BorderLayout.WEST);
        add(buildTablePanel(), BorderLayout.CENTER);

        toast.setFont(Theme.BOLD);
        toast.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 0));
        add(toast, BorderLayout.SOUTH);

        clearForm();
        setSize(1180, 700);
        setMinimumSize(new Dimension(980, 560));
        setLocationRelativeTo(null);
        refresh();
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
        JLabel subtitle = new JLabel("Report, track and escalate security incidents");
        subtitle.setFont(Theme.BASE);
        subtitle.setForeground(new Color(0xD6E6F5));

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setBorder(BorderFactory.createEmptyBorder(14, 20, 14, 20));
        text.add(title);
        text.add(subtitle);
        header.add(text, BorderLayout.CENTER);
        return header;
    }

    private JPanel buildDashboard() {
        JPanel panel = new JPanel(new GridLayout(1, 5, 12, 0));
        panel.setOpaque(false);
        panel.add(totalCard);
        panel.add(activeCard);
        panel.add(closedCard);
        panel.add(highCard);
        panel.add(queueCard);
        return panel;
    }

    private static Border inputBorder() {
        return BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.LINE),
                BorderFactory.createEmptyBorder(5, 8, 5, 8));
    }

    private JPanel buildForm() {
        RoundPanel panel = new RoundPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        panel.setPreferredSize(new Dimension(320, 0));

        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        descArea.setFont(Theme.BASE);
        descArea.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8));
        reporterField.setFont(Theme.BASE);
        reporterField.setBorder(inputBorder());
        JScrollPane descScroll = new JScrollPane(descArea);
        descScroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        for (JComboBox<String> box : Arrays.asList(typeBox, severityBox, statusBox)) {
            box.setFont(Theme.BASE);
            box.setBackground(Color.WHITE);
        }

        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0;
        g.gridy = -1;
        g.weightx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.insets = new Insets(3, 0, 3, 0);

        JLabel heading = new JLabel("Incident form");
        heading.setFont(Theme.BASE.deriveFont(Font.BOLD, 16f));
        heading.setForeground(Theme.BRAND);
        g.gridy++;
        panel.add(heading, g);

        addField(panel, g, "Incident type", typeBox);
        addField(panel, g, "Reporter name", reporterField);
        addField(panel, g, "Description", descScroll);
        addField(panel, g, "Severity", severityBox);
        addField(panel, g, "Status (when editing)", statusBox);

        RoundButton addBtn = new RoundButton("Add", Theme.BRAND, Color.WHITE);
        RoundButton viewBtn = new RoundButton("View details", new Color(0xE3ECF5), Theme.BRAND);
        RoundButton updateBtn = new RoundButton("Update", Theme.LOW, Color.WHITE);
        RoundButton deleteBtn = new RoundButton("Delete", Theme.CRITICAL, Color.WHITE);
        RoundButton clearBtn = new RoundButton("Clear form", new Color(0xEEF1F4), Theme.INK);

        addBtn.addActionListener(e -> perform(this::addIncident));
        viewBtn.addActionListener(e -> perform(this::viewIncident));
        updateBtn.addActionListener(e -> perform(this::updateIncident));
        deleteBtn.addActionListener(e -> perform(this::deleteIncident));
        clearBtn.addActionListener(e -> clearForm());

        JPanel buttons = new JPanel(new GridLayout(3, 2, 8, 8));
        buttons.setOpaque(false);
        buttons.add(addBtn);
        buttons.add(viewBtn);
        buttons.add(updateBtn);
        buttons.add(deleteBtn);
        buttons.add(clearBtn);
        g.gridy++;
        g.insets = new Insets(14, 0, 3, 0);
        panel.add(buttons, g);

        g.gridy++;
        g.weighty = 1;
        panel.add(Box.createVerticalGlue(), g);
        return panel;
    }

    private void addField(JPanel panel, GridBagConstraints g, String label, Component field) {
        JLabel text = new JLabel(label);
        text.setFont(Theme.BOLD.deriveFont(12f));
        text.setForeground(Theme.MUTED);
        g.gridy++;
        panel.add(text, g);
        g.gridy++;
        panel.add(field, g);
    }

    private JPanel buildTablePanel() {
        RoundPanel panel = new RoundPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        RoundButton searchBtn = new RoundButton("Search", Theme.BRAND, Color.WHITE);
        RoundButton escalateBtn = new RoundButton("Process next escalation", Theme.HIGH, Color.WHITE);
        searchBtn.addActionListener(e -> perform(this::searchIncident));
        escalateBtn.addActionListener(e -> perform(this::escalateNext));
        highOnly.setOpaque(false);
        highOnly.setFont(Theme.BASE);
        highOnly.addActionListener(e -> refresh());
        searchField.setFont(Theme.BASE);
        searchField.setBorder(inputBorder());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        bar.setOpaque(false);
        bar.add(new JLabel("Incident ID:"));
        bar.add(searchField);
        bar.add(searchBtn);
        bar.add(highOnly);
        bar.add(escalateBtn);

        styleTable();
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        scroll.getViewport().setBackground(Color.WHITE);

        panel.add(bar, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private void styleTable() {
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFont(Theme.BASE);
        table.setRowHeight(30);
        table.setShowVerticalLines(false);
        table.setGridColor(Theme.LINE);
        table.setIntercellSpacing(new Dimension(0, 1));

        RowRenderer renderer = new RowRenderer();
        table.setDefaultRenderer(Object.class, renderer);
        table.setDefaultRenderer(String.class, renderer);
        table.setDefaultRenderer(Integer.class, renderer);

        table.getTableHeader().setPreferredSize(new Dimension(0, 34));
        table.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean s, boolean f, int r, int c) {
                super.getTableCellRendererComponent(t, v, false, false, r, c);
                setBackground(Theme.BRAND);
                setForeground(Color.WHITE);
                setFont(Theme.BOLD);
                setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                setHorizontalAlignment(c == 0 || c >= 4 ? CENTER : LEFT);
                return this;
            }
        });

        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(3).setPreferredWidth(280);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadForm();
            }
        });
    }

    // Colours rows: stripes, coloured severity/status text and the highlight flash
    private class RowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            super.getTableCellRendererComponent(t, value, false, false, row, col);
            setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
            setHorizontalAlignment(col == 0 || col >= 4 ? CENTER : LEFT);

            Color bg = row % 2 == 0 ? Color.WHITE : new Color(0xF5F8FB);
            if (flashAlpha > 0f && t.getValueAt(row, 0).equals(flashId)) {
                bg = Theme.blend(bg, new Color(0xFFE08A), flashAlpha);
            }
            if (sel) {
                bg = new Color(0xD6E6F5);
            }
            setBackground(bg);
            setForeground(Theme.INK);
            setFont(Theme.BASE);
            if (col == 4) {
                setForeground(Theme.severity(String.valueOf(value)));
                setFont(Theme.BOLD);
            } else if (col == 5) {
                setForeground(Theme.status(String.valueOf(value)));
                setFont(Theme.BOLD);
            }
            return this;
        }
    }

    // ---------- Button actions ----------
    private void addIncident() throws InvalidInputException {
        if (selectedId() != null) {
            throw new InvalidInputException("A row is selected. Click \"Clear form\" before adding a new incident.");
        }
        SecurityIncident incident = manager.report((String) typeBox.getSelectedItem(),
                reporterField.getText(), descArea.getText(), (String) severityBox.getSelectedItem());
        clearForm();
        flashRow(incident.getId());
        toast("Incident #" + incident.getId() + " reported successfully.");
    }

    private void viewIncident() throws InvalidInputException, IncidentNotFoundException {
        int id = requireSelected();
        showDetails("Incident #" + id, manager.find(id).describe(false));
    }

    private void updateIncident()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        int id = requireSelected();
        manager.update(id, reporterField.getText(), descArea.getText(),
                (String) severityBox.getSelectedItem(), (String) statusBox.getSelectedItem());
        flashRow(id);
        toast("Incident #" + id + " has been updated.");
    }

    private void deleteIncident() throws InvalidInputException, IncidentNotFoundException {
        int id = requireSelected();
        SecurityIncident incident = manager.find(id);
        int answer = JOptionPane.showConfirmDialog(this,
                "Delete this incident permanently?\n\n" + incident.describe(true),
                "Confirm delete", JOptionPane.YES_NO_OPTION);
        if (answer == JOptionPane.YES_OPTION) {
            manager.delete(id);
            clearForm();
            toast("Incident #" + id + " has been deleted.");
        }
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

    private void escalateNext() {
        showDetails("Escalation", manager.processNextEscalation());
    }

    // ---------- Error handling: pop-ups instead of crashes ----------
    private void perform(UiAction action) {
        try {
            action.run();
        } catch (InvalidInputException | IncidentNotFoundException | IncidentClosedException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
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
        for (SecurityIncident i : manager.getIncidents()) {
            if (highOnly.isSelected() && !i.requiresEscalation()) {
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

    private void loadForm() {
        Integer id = selectedId();
        if (id == null) {
            typeBox.setEnabled(true);
            statusBox.setEnabled(false);
            return;
        }
        try {
            SecurityIncident i = manager.find(id);
            typeBox.setSelectedItem(i.getIncidentType());
            reporterField.setText(i.getReporter());
            descArea.setText(i.getDescription());
            severityBox.setSelectedItem(i.getSeverity());
            statusBox.setSelectedItem(i.getStatus());
            typeBox.setEnabled(false);
            statusBox.setEnabled(true);
        } catch (IncidentNotFoundException e) {
            clearForm();
        }
    }

    private void clearForm() {
        table.clearSelection();
        reporterField.setText("");
        descArea.setText("");
        typeBox.setSelectedIndex(0);
        severityBox.setSelectedItem("Medium");
        statusBox.setSelectedItem("Open");
        typeBox.setEnabled(true);
        statusBox.setEnabled(false);
    }

    private void showDetails(String title, String text) {
        JTextArea area = new JTextArea(text, 11, 42);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        JOptionPane.showMessageDialog(this, new JScrollPane(area), title, JOptionPane.INFORMATION_MESSAGE);
    }
}
