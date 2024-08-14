# Description
Decided to upload this old project to GitHub. This is the source code from my graduate diploma titled "Development of DRM Protection for Windows XP" which I presented in 2008. This project aimed to demonstrate some Windows Internals and driver development stuff in the context of DRM protection. It consists of several projects:
* Legacy FS filter driver with features such as providing interactive blocking access to file operations and hiding files for specific processes.
* Keylogger with advanced features, it saves keystrokes with the current keyboard layout to the specified files and is activated before the user is authenticated in the system. It includes a driver, DLL that provides API to the driver and a Windows service.
* Separate user mode tools for testing aforementioned features.

Architecture of the keylogger components.

![alt text](https://github.com/user-attachments/assets/924cfeb7-ba07-433e-9d2c-44d46fed423b)

# Build
It can be built with modern versions of Visual Studio, having previously converted the solution and project files (automatically).
