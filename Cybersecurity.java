import java.util.ArrayList;
import java.util.Scanner;

public class Cybersecurity {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        IncidentManager manager = new IncidentManager(scanner);
        manager.run();
        scanner.close();
    }
}

abstract class SecurityIncident {
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

    public void displayDetails() {
        System.out.println("\nIncident ID: " + id);
        System.out.println("Type: " + getIncidentType());
        System.out.println("Reporter: " + reporter);
        System.out.println("Description: " + description);
        System.out.println("Severity: " + severity);
        System.out.println("Status: " + status);
        System.out.println("Recommended Response: " + recommendResponse());
        System.out.println("-----------------------------------");
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
}


class IncidentManager {
    private ArrayList<SecurityIncident> incidents = new ArrayList<>();
    private Scanner scanner;
    private int nextId = 1;

    public IncidentManager(Scanner scanner) {
        this.scanner = scanner;
    }

    public void run() {
        int choice;

        do {
            System.out.println("\n===== CYBERSECURITY INCIDENT SYSTEM =====");
            System.out.println("1. Report Security Incident");
            System.out.println("2. View All Incidents");
            System.out.println("3. Search Incident");
            System.out.println("4. Assign Severity Level");
            System.out.println("5. Update Investigation Status");
            System.out.println("6. View High-Severity Incidents");
            System.out.println("7. Close Incident");
            System.out.println("8. Exit");

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
                    System.out.println("Exiting Cybersecurity Incident System.");
                    break;
                default:
                    System.out.println("Invalid choice. Please select 1 to 8.");
            }
        } while (choice != 8);
    }

    private void reportIncident() {
        System.out.println("\nIncident Types");
        System.out.println("1. Malware");
        System.out.println("2. Phishing");
        System.out.println("3. Unauthorized Access");

        int type = readInt("Choose incident type: ");

        if (type < 1 || type > 3) {
            System.out.println("Invalid incident type.");
            return;
        }

        System.out.print("Enter reporter name: ");
        String reporter = scanner.nextLine().trim();

        if (reporter.isEmpty()) {
            System.out.println("Reporter name cannot be empty.");
            return;
        }

        System.out.print("Describe the incident: ");
        String description = scanner.nextLine().trim();

        if (description.isEmpty()) {
            System.out.println("Incident description cannot be empty.");
            return;
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

    private void searchIncident() {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);

        if (incident == null) {
            System.out.println("Incident not found.");
        } else {
            incident.displayDetails();
        }
    }

    private void assignSeverity() {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);

        if (incident == null) {
            System.out.println("Incident not found.");
            return;
        }

        if (incident.getStatus().equals("Closed")) {
            System.out.println("Cannot change the severity of a closed incident.");
            return;
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
                System.out.println("Invalid severity choice.");
                return;
        }

        incident.setSeverity(severity);
        System.out.println("Severity updated to " + severity + ".");
    }

    private void updateStatus() {
        int id = readInt("Enter incident ID: ");
        SecurityIncident incident = findIncident(id);

        if (incident == null) {
            System.out.println("Incident not found.");
            return;
        }

        if (incident.getStatus().equals("Closed")) {
            System.out.println("This incident is already closed.");
            return;
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
                System.out.println("Invalid status choice.");
                return;
        }

        incident.setStatus(status);
        System.out.println("Incident status updated to " + status + ".");
    }

    private void viewHighSeverityIncidents() {
        boolean found = false;

        for (SecurityIncident incident : incidents) {
            if (incident.getSeverity().equals("High")
                    || incident.getSeverity().equals("Critical")) {
                incident.displayDetails();
                found = true;
            }
        }

        if (!found) {
            System.out.println("No high-severity incidents found.");
        }
    }

    private void closeIncident() {
        int id = readInt("Enter incident ID to close: ");
        SecurityIncident incident = findIncident(id);

        if (incident == null) {
            System.out.println("Incident not found.");
            return;
        }

        if (incident.getStatus().equals("Closed")) {
            System.out.println("This incident is already closed.");
            return;
        }

        incident.setStatus("Closed");
        System.out.println("Incident #" + id + " has been closed.");
    }

    private SecurityIncident findIncident(int id) {
        for (SecurityIncident incident : incidents) {
            if (incident.getId() == id) {
                return incident;
            }
        }

        return null;
    }

    private int readInt(String prompt) {
        while (true) {
            System.out.print(prompt);
            String input = scanner.nextLine().trim();

            try {
                return Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Please enter a valid whole number.");
            }
        }
    }
}
