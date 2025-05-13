# PhishingDetector

PhishingDetector is a comprehensive system designed to detect and prevent phishing attempts using a combination of a browser extension, backend analysis, and a user-friendly web interface.

## Repository Structure

This is the parent repository that organizes the project into three main components:

1. **[PhishingExtension](./PhishingExtension)**  
   A firefox extension that monitors URLs and user actions to detect potential phishing threats in real time.

2. **[PhishingUI](./PhishingUI)**  
   A modern frontend interface that allows users to interact with the system, review detected threats, and manage their preferences.

3. **[PhishingBackend](./PhishingBackend)**  
   A backend server that handles detection logic, database management, and communication with the extension and UI.

## Getting Started

To set up the project locally:

1. Clone this repository and its submodules (if applicable):

   ```bash
   git clone --recurse-submodules https://github.com/devfernandoa/PhishingDetector.git
   ```

2. Follow the setup instructions in each component's README:
   - [PhishingExtension](./PhishingExtension/README.md)
   - [PhishingUI](./PhishingUI/README.md)
   - [PhishingBackend](./PhishingBackend/README.md)

3. Each project is hosted on it's own website:
   - [Phishing Extension](https://addons.mozilla.org/en-US/firefox/addon/phishing-detector-extension/)
   - [Phishing UI](https://phishing.fernandoa.dev/)
   - [Phishing Backend](https://phishingdetector-production-a575.up.railway.app/analyze?url=google.com)

## License

This project is licensed under the MIT License. See the LICENSE file for details.
