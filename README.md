# --==[[ Certipy JSON Viewer ]]==--

A Flask-based web application for viewing and analyzing Certipy JSON output files. This tool helps visualize and assess Active Directory Certificate Services (AD CS) configurations and identify potential vulnerabilities.

![](https://raw.githubusercontent.com/incredibleindishell/Certipy-JSON-Viewer/refs/heads/main/images/1.png)

## Features

- **SQLite Database Storage**: Store multiple Certipy assessment projects
- **File Upload Interface**: Easy-to-use web form for uploading JSON files
- **Vulnerability Detection**: Automatically detects ESC1, ESC2, ESC3, ESC4, ESC8 and ESC15 vulnerabilities
- **Detailed Analysis**: Comprehensive view of certificate templates, permissions, and flags
- **Imported Data Management**: View, search, and delete projects

## Installation

### Prerequisites

- Python 3.7+
- pip

### Setup

1. Install Flask:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:8000
```

## Usage

### 1. Generate Certipy JSON Output

First, run Certipy to enumerate certificate templates in your target Active Directory environment:

```bash
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10
```

This will generate a JSON file (e.g., `20260210123456_Certipy.json`)

### 2. Upload to the Viewer

1. Navigate to the "Upload Project" page
2. Enter a descriptive project name (e.g., "Indishell Lab")
3. Select the Certipy JSON file
4. Click "Upload Project"

![](https://raw.githubusercontent.com/incredibleindishell/Certipy-JSON-Viewer/refs/heads/main/images/2.png)

### 3. View Analysis

1. Go to "View Projects" to see all uploaded JSON results

![](https://raw.githubusercontent.com/incredibleindishell/Certipy-JSON-Viewer/refs/heads/main/images/3.png)

2. Click "View Analysis" on any project to see:
   - Certificate template details
   - Enrollment and private key flags
   - Extended Key Usage (EKU) information
   - Access Control Lists (ACLs)
   - Detected vulnerabilities

![](https://raw.githubusercontent.com/incredibleindishell/Certipy-JSON-Viewer/refs/heads/main/images/4.png)

For a vulnerable certificate template, details will be displayed like this:

![](https://raw.githubusercontent.com/incredibleindishell/Certipy-JSON-Viewer/refs/heads/main/images/5.png)

## Vulnerability Detection

The tool automatically detects the following AD CS vulnerabilities:

- **ESC1**: Domain Escalation via Enrollee-Supplied Subject + Client Authentication
- **ESC2**: Any Purpose EKU allows certificates for any purpose
- **ESC3**: Enrollment Agent template abuse
- **ESC4**: Vulnerable ACL permissions (WriteDacl/WriteOwner for low-privileged users)
- **ESC8**: Web Enrollment Endpoint is Enabled and no Channel Binding enabled
- **ESC15**: Enrollee-Supplied Subject + Template Schema version 1

## Credits

- **Certipy**: https://github.com/ly4k/Certipy
- SpecterOps for AD CS research
- Dominic Sir, Matt Johnson bhai ji, PWS, Daniil, Dylan, Zero cool, Code Breaker ICA, Indishell Crew
- Ashwath, Andy, Marcus and Soroush sir
- RGO members: Konsta, Noman, Owais, Etizaz, Sina, Aleseendro, Samarth, Roshan
- Partner in crime: Karan and Manoj
