import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Queue;
import java.util.Scanner;

public class Cybersecurity {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            IncidentManager manager = new IncidentManager(scanner);
            manager.run();
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }
}

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

interface Reportable {
    String generateReport();
}

interface Escalatable {
    boolean requiresEscalation();
}

abstract class SecurityIncident implements Reportable, Escalatable {
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

    public int getId() {
        return id;
    }

    public String getReporter() {
        return reporter;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    public String getStatus() {
        return status;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public abstract String getIncidentType();
    public abstract String recommendResponse();
    public abstract int getBaseRiskScore();

    public int calculateRiskScore() {
        int weight;
        switch (severity) {
            case "Medium":
                weight = 1;
                break;
            case "High":
                weight = 2;
                break;
            case "Critical":
                weight = 3;
                break;
            default:
                weight = 0;
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

    public void displayDetails() {
        System.out.println("\nIncident ID: " + id);
        System.out.println("Type: " + getIncidentType());
        System.out.println("Reporter: " + reporter);
        System.out.println("Description: " + description);
        System.out.println("Severity: " + severity);
        System.out.println("Status: " + status);
        System.out.println("Risk Score: " + calculateRiskScore());
        System.out.println("Recommended Response: " + recommendResponse());
        System.out.println("-----------------------------------");
    }

    public void displayDetails(boolean brief) {
        if (brief) {
            System.out.println(generateReport());
        } else {
            displayDetails();
        }
    }
}

class MalwareIncident extends SecurityIncident {
    public MalwareIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() {
        return "Malware";
    }

    @Override
    public String recommendResponse() {
        return "Isolate the affected device and scan it using approved security software.";
    }

    @Override
    public int getBaseRiskScore() {
        return 7;
    }
}

class PhishingIncident extends SecurityIncident {
    public PhishingIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() {
        return "Phishing";
    }

    @Override
    public String recommendResponse() {
        return "Avoid clicking suspicious links and report the message to the security team.";
    }

    @Override
    public int getBaseRiskScore() {
        return 5;
    }
}

class UnauthorizedAccessIncident extends SecurityIncident {
    public UnauthorizedAccessIncident(int id, String reporter, String description, String severity) {
        super(id, reporter, description, severity);
    }

    @Override
    public String getIncidentType() {
        return "Unauthorized Access";
    }

    @Override
    public String recommendResponse() {
        return "Review access logs, secure the affected account, and investigate suspicious activity.";
    }

    @Override
    public int getBaseRiskScore() {
        return 8;
    }
}

class IncidentManager {
    private static final int EXIT_CHOICE = 10;

    private ArrayList<SecurityIncident> incidents = new ArrayList<>();
    private HashMap<Integer, SecurityIncident> incidentMap = new HashMap<>();
    private Queue<SecurityIncident> escalationQueue = new LinkedList<>();
    private Scanner scanner;
    private int nextId = 1;

    public IncidentManager(Scanner scanner) {
        this.scanner = scanner;
    }

    public void run() {
        int choice = 0;

        do {
            System.out.println("\n===== CYBERSECURITY INCIDENT SYSTEM =====");
            System.out.println("1. Report Security Incident");
            System.out.println("2. View All Incidents");
            System.out.println("3. Search Incident");
            System.out.println("4. Assign Severity Level");
            System.out.println("5. Update Investigation Status");
            System.out.println("6. View High-Severity Incidents");
            System.out.println("7. Close Incident");
            System.out.println("8. Delete Incident");
            System.out.println("9. Process Next Escalation");
            System.out.println("10. Exit");

            try {
                choice = readInt("Enter your choice: ");

                switch (choice) {
                    case 1:
                        reportIncident();
                        break;
                    case 2:
                        viewAllIncidents();
                        break;
                    case 3:
                        searchIncident();
                        break;
                    case 4:
                        assignSeverity();
                        break;
                    case 5:
                        updateStatus();
                        break;
                    case 6:
                        viewHighSeverityIncidents();
                        break;
                    case 7:
                        closeIncident();
                        break;
                    case 8:
                        deleteIncident();
                        break;
                    case 9:
                        processNextEscalation();
                        break;
                    case EXIT_CHOICE:
                        System.out.println("Exiting Cybersecurity Incident System.");
                        break;
                    default:
                        throw new InvalidInputException("Invalid choice. Please select 1 to 10.");
                }
            } catch (InvalidInputException | IncidentNotFoundException | IncidentClosedException e) {
                System.out.println("Error: " + e.getMessage());
            } catch (NoSuchElementException e) {
                System.out.println("\nInput ended unexpectedly. Exiting.");
                choice = EXIT_CHOICE;
            } catch (Exception e) {
                System.out.println("Unexpected error: " + e.getMessage());
            } finally {
                if (choice != EXIT_CHOICE) {
                    System.out.println("(Returning to main menu...)");
                }
            }
        } while (choice != EXIT_CHOICE);
    }

    private void reportIncident() throws InvalidInputException {
        System.out.println("\nIncident Types");
        System.out.println("1. Malware");
        System.out.println("2. Phishing");
        System.out.println("3. Unauthorized Access");

        int type = readInt("Choose incident type: ");

        if (type < 1 || type > 3) {
            throw new InvalidInputException("Invalid incident type.");
        }

        System.out.print("Enter reporter name: ");
        String reporter = scanner.nextLine().trim();

        if (reporter.isEmpty()) {
            throw new InvalidInputException("Reporter name cannot be empty.");
        }

        System.out.print("Describe the incident: ");
        String description = scanner.nextLine().trim();

        if (description.isEmpty()) {
            throw new InvalidInputException("Incident description cannot be empty.");
        }

        SecurityIncident incident;

        switch (type) {
            case 1:
                incident = new MalwareIncident(
                    nextId, reporter, description, "Medium"
                );
                break;
            case 2:
                incident = new PhishingIncident(
                    nextId, reporter, description, "Medium"
                );
                break;
            default:
                incident = new UnauthorizedAccessIncident(
                    nextId, reporter, description, "Medium"
                );
                break;
        }

        incidents.add(incident);
        incidentMap.put(incident.getId(), incident);

        System.out.println("Incident reported successfully.");
        System.out.println("Assigned Incident ID: " + nextId);

        nextId++;
    }

    private void viewAllIncidents() {
        if (incidents.isEmpty()) {
            System.out.println("No incidents have been reported.");
            return;
        }

        for (SecurityIncident incident : incidents) {
            incident.displayDetails();
        }
    }

    private void searchIncident() throws InvalidInputException, IncidentNotFoundException {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);
        incident.displayDetails();
    }

    private void assignSeverity()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);

        if (incident.getStatus().equals("Closed")) {
            throw new IncidentClosedException("Cannot change the severity of a closed incident.");
        }

        System.out.println("1. Low");
        System.out.println("2. Medium");
        System.out.println("3. High");
        System.out.println("4. Critical");

        int choice = readInt("Select severity: ");
        String severity;

        switch (choice) {
            case 1:
                severity = "Low";
                break;
            case 2:
                severity = "Medium";
                break;
            case 3:
                severity = "High";
                break;
            case 4:
                severity = "Critical";
                break;
            default:
                throw new InvalidInputException("Invalid severity choice.");
        }

        incident.setSeverity(severity);
        System.out.println("Severity updated to " + severity + ".");

        if (incident.requiresEscalation() && !escalationQueue.contains(incident)) {
            escalationQueue.add(incident);
            System.out.println("Incident #" + id + " added to the escalation queue.");
        }
    }

    private void updateStatus()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);

        if (incident.getStatus().equals("Closed")) {
            throw new IncidentClosedException("This incident is already closed.");
        }

        System.out.println("1. Open");
        System.out.println("2. Under Investigation");
        System.out.println("3. Resolved");

        int choice = readInt("Select new status: ");
        String status;

        switch (choice) {
            case 1:
                status = "Open";
                break;
            case 2:
                status = "Under Investigation";
                break;
            case 3:
                status = "Resolved";
                break;
            default:
                throw new InvalidInputException("Invalid status choice.");
        }

        incident.setStatus(status);
        System.out.println("Incident status updated to " + status + ".");
    }

    private void viewHighSeverityIncidents() {
        boolean found = false;

        for (SecurityIncident incident : incidents) {
            if (incident.requiresEscalation()) {
                incident.displayDetails();
                found = true;
            }
        }

        if (!found) {
            System.out.println("No high-severity incidents found.");
        }
    }

    private void closeIncident()
            throws InvalidInputException, IncidentNotFoundException, IncidentClosedException {
        int id = readInt("Enter incident ID to close: ");
        SecurityIncident incident = findIncident(id);

        if (incident.getStatus().equals("Closed")) {
            throw new IncidentClosedException("This incident is already closed.");
        }

        incident.setStatus("Closed");
        escalationQueue.remove(incident);
        System.out.println("Incident #" + id + " has been closed.");
    }

    private void deleteIncident() throws InvalidInputException, IncidentNotFoundException {
        int id = readInt("Enter incident ID to delete: ");
        SecurityIncident incident = findIncident(id);

        incident.displayDetails(true);
        System.out.print("Delete this incident permanently? (yes/no): ");
        String confirm = scanner.nextLine().trim();

        if (confirm.equalsIgnoreCase("yes") || confirm.equalsIgnoreCase("y")) {
            incidents.remove(incident);
            incidentMap.remove(id);
            escalationQueue.remove(incident);
            System.out.println("Incident #" + id + " has been deleted.");
        } else {
            System.out.println("Deletion cancelled.");
        }
    }

    private void processNextEscalation() {
        SecurityIncident incident;

        while ((incident = escalationQueue.poll()) != null) {
            if (!incident.getStatus().equals("Closed") && incident.requiresEscalation()) {
                System.out.println("Escalating next incident for review:");
                incident.displayDetails();

                if (incident.getStatus().equals("Open")) {
                    incident.setStatus("Under Investigation");
                    System.out.println("Status changed to Under Investigation.");
                }
                System.out.println("Incidents still waiting in queue: " + escalationQueue.size());
                return;
            }
        }

        System.out.println("No incidents are waiting for escalation.");
    }

    private SecurityIncident findIncident(int id) throws IncidentNotFoundException {
        SecurityIncident incident = incidentMap.get(id);

        if (incident == null) {
            throw new IncidentNotFoundException(id);
        }

        return incident;
    }

    private int readInt(String prompt) throws InvalidInputException {
        System.out.print(prompt);
        String input = scanner.nextLine().trim();

        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException e) {
            throw new InvalidInputException("Please enter a valid whole number.");
        }
    }
}
