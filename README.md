![flexihome-logo](docs/logo/flexihome-logo.png)

---

# FlexiHome: A Home Energy Management System 🔌<br><br>Account Manager


## Description

This repository contains the Account Manager Service, a core component of the Home Energy Management System (FlexiHome). The Account Manager Service is responsible for managing user accounts, authentication, and authorization within the FlexiHome ecosystem. It provides secure access to various functionalities and services offered by the FlexiHome platform.

## Table of Contents

- [FlexiHome: A Home Energy Management System 🔌Account Manager](#flexihome-a-home-energy-management-system-account-manager)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [FlexiHome Overview](#flexihome-overview)
    - [Visit all the FlexiHome micro-services:](#visit-all-the-flexihome-micro-services)
  - [Project details](#project-details)
    - [📂 Repository Structure](#-repository-structure)
    - [Project Status](#project-status)
    - [Technology Stack](#technology-stack)
    - [Dependencies](#dependencies)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Known Issues](#known-issues)
  - [Open Source Licensing Info](#open-source-licensing-info)
    - [Contacts](#contacts)

## FlexiHome Overview

EMSs (Energy Management Systems) play a key role in the flexibility enablement of consumers, residential and tertiary, which is paramount to accessing the previously untapped flexibility potential of residential DERs (Distributed Energy Resources). These resources, under the form of energy assets, are usually household appliances like heat pumps, EV chargers, dishwashers, PV inverts, batteries, etc. This is where the FlexiHome (Home Energy Management System) comes in. 

The goal of this system is to facilitate the user’s participation in the flexibility value chain, while providing them with incentives in a clear, explainable way.

To fulfill this goal in an effective and scalable way, the FlexiHome is designed with a micro-services architecture (below), orchestrated in a Kubernetes environment, where each micro-service is modular and can be replaced or expanded, without breaking the remaining logic.

![FlexiHome Architecture](docs/diagrams/hems-architecture-diagram.svg)

FlexiHome utilizes an IoT interoperable gateway (FlexiHome Hub) to connect to the end users DERs via interoperable protocols like OCPP and Modbus, which connects with the cloud system (FlexiHome Cloud) via an MQTT message broker.

The cloud operations are done via micro-services, where the flexibility optimization algorithms run. To complement these micro-services, support applications like postgres (database), elasticsearch (log database), prometheus (performance metrics) and grafana (metrics dashboard) are used.

Lastly, the user can view the information regarding their devices and flexibility on a user interface provided by the mobile app, which accesses the FlexiHome microservices using a REST API Gateway for additional security measures and routing of requests.

### Visit all the FlexiHome micro-services:
- [FlexiHome Account Manager](https://github.com/INESCTEC/hems-account-manager) - Manages user accounts, authentication, and implements cybersecurity measures within the FlexiHome ecosystem
- [FlexiHome Statistics Manager](https://github.com/INESCTEC/hems-statistics-manager) - Collects and processes data gathered from IoT devices connected to the FlexiHome ecosystem
- [FlexiHome Device Manager](https://github.com/INESCTEC/hems-device-manager) - Responsible for the integration and management of IoT devices to the FlexiHome ecosystem
- [FlexiHome Energy Manager](https://github.com/INESCTEC/hems-energy-manager) - Receives grid needs inputs from system operators and user comfort inputs to optimized the flexibility bids taken to market 
- [FlexiHome Hub](https://github.com/INESCTEC/hems-hub) - IoT interoperable gateway that implements the communication, using MQTT protocol, between the DERs and the FlexiHome services on the cloud
- [FlexiHome Mobile App](https://github.com/INESCTEC/hems-app) - mobile application targetted for residential end consumers to manage their flexible DERs. Available in Android and iOS


## Project details

### 📂 Repository Structure

```bash
.                      # Root directory of the repository
├── account_manager     # Main source code for the Account Manager Service
│   ├── controllers/    # API controllers for account management
│   ├── models/         # Data models and schemas
│   ├── templates/      # HTML templates for emails and UI
│   ├── test/           # Unit and integration tests
│   └── ...             # Other supporting modules
├── Dockerfile          # Docker configuration for containerization
├── LICENSE             # Rights and licensing information
├── requirements.txt    # Python dependencies
├── README.md           # Main documentation
├── setup.py            # Python package setup
├── service-start.sh    # Service startup script
├── Docker-compose/     # Docker Compose files and monitoring configs
├── docs/               # Documentation and architecture diagrams
```


### Project Status

- 🚧 In Progress: Actively being developed; features and structure may change.


### Technology Stack

- **Programming Language:** Python 3.8
- **Frameworks/Libraries:** Flask, SQLAlchemy, Alembic
- **Containerization:** Docker, Docker Compose
- **Orchestration:** Kubernetes (recommended for deployment)
- **Other Tools:** Alembic (migrations), pytest (testing)


### Dependencies

All required Python packages are listed in `requirements.txt`. For testing, see `test-requirements.txt`. Docker and Docker Compose are required for containerized deployments.


## Installation

Follow these steps to install and set up the Account Manager Service:

1. **Clone the repository:**
  ```bash
  git clone https://github.com/INESCTEC/hems-account-manager.git
  cd account-manager-service
  ```

2. **Create and activate a virtual environment:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate  # On Windows: venv\Scripts\activate
  ```

3. **Install dependencies:**
  ```bash
  pip install -r requirements.txt
  ```

4. **Set up environment variables:**
  ```bash
  cp .env.example .env
  nano .env  # Edit with your configuration values
  ```

5. **(Optional) Build and run with Docker:**
  ```bash
  docker-compose up --build
  ```


## Usage

To start the Account Manager Service:

```bash
source venv/bin/activate
python -m account_manager
```

Or, if using Docker Compose:

```bash
cd Docker-compose
docker-compose -f docker-compose-prod.yml up
```

Access the API documentation and endpoints as defined in the OpenAPI spec (`account_manager/openapi/openapi.yaml`), which can be open using [Swagger Editor](https://editor.swagger.io/)


## Known Issues

- No major issues reported. Please use GitHub Issues to report bugs or request features.


## Open Source Licensing Info

See [`LICENSE`](LICENSE) for details on usage rights and licensing.


### Contacts

For questions or support, contact:
- Vasco Manuel Campos: vasco.m.campos@inesctec.pt
- Daniel Barros: daniel.barros@inesctec.pt
