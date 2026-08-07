#include <iostream>
#include <string>
using namespace std;

class Car {
    public:
        string name;
        double distance;
        
        Car(string n, double d) {
            name = n;
            distance = d;
        }

    void display() {
            cout << "Driver's Name: " << name << endl;
            cout << "Distance: " << distance << " km" << endl;
        }
};

class GrabSaver : public Car {
    public:
    GrabSaver(string n, double d) : Car(n, d) {}

    double fareCalc() {
        return 45 + (distance * 15);

    }
    
    void timeCalc() {
        double time = distance / 30;
        cout << "Estimated Time: " << time << " hours" << endl;
    }
};

class GrabTaxi : public Car {
    public:
    GrabTaxi(string n, double d) : Car(n, d) {}

    double fareCalc() {
        return 60 + (distance * 15);
    }
    
    void timeCalc() {
        double time = distance / 40;
        cout << "Estimated Time: " << time << " hours" << endl;
    }
};

class GrabCar : public Car {
    public:
    GrabCar(string n, double d) : Car(n, d) {}

    double fareCalc() {
        return 75 + (distance * 20);
    }
    
    void timeCalc() {
        double time = distance / 50;
        cout << "Estimated Time: " << time << " hours" << endl;
    }
};

int main() {
    string name;
    double distance = 0, time;
    int earnings = 0, choice;
    char anotherRide = 'y';

    cout << "===== Welcome to Grab =====" << endl;
    cout << "Enter Your Name: ";
    cin >> name;
    cout << "What service do you want to do?" << endl;
    cout << "1. GrabSaver" << endl;
    cout << "2. GrabTaxi" << endl;
    cout << "3. GrabCar" << endl;
    cout << "Enter your choice: ";
    cin >> choice;
    cout << endl;

    do {
        cout << "You Picked Up a Passenger! Please Enter Distance Based From Your Maps (km): ";
        cin >> distance;
        do {
            if (distance <= 0) {
                cout << "Invalid distance. Please enter a positive value." << endl;
                cout << "Enter Distance (km): ";
                cin >> distance;
            }
        } while (distance <= 0);

        do {
            if (choice == 1) {
                GrabSaver gs(name, distance);
                gs.timeCalc();
                earnings += gs.fareCalc();
                cout << "Current Earnings: Php " << earnings << endl;
            }
            else if (choice == 2) {
                GrabTaxi gt(name, distance);
                gt.timeCalc();
                earnings += gt.fareCalc();
                cout << "Current Earnings: Php " << earnings << endl;
            }
            else if (choice == 3) {
                GrabCar gc(name, distance);
                gc.timeCalc();
                earnings += gc.fareCalc();
                cout << "Current Earnings: Php " << earnings << endl;
            }
            else {
                cout << "Invalid choice. Please select a valid ride option." << endl;
            }
        } while (choice < 1 || choice > 3);

    cout << "Do you want to take another ride? (y/n): ";
    cin >> anotherRide;
    while (anotherRide != 'y' && anotherRide != 'n') {
        cout << "Invalid input. Please enter 'y' for yes or 'n' for no." << endl;
        cout << "Do you want to take another ride? (y/n): ";
        cin >> anotherRide;
    }

    cout << endl;

    } while  (anotherRide == 'y' || anotherRide == 'Y');

    cout << name << ", you have completed your shift for today!" << endl;
    cout << "FINAL EARNINGS: Php " << earnings << endl;
    cout << "System stopped." << endl;

    return 0;
}
