# Cyber Attack Type Detection and Defense Mechanisms

This project provides a machine learning–based solution for detecting cyber attacks and suggesting appropriate defense actions. It uses an XGBoost classifier that is trained on a set of network traffic and cyber activity features. Once the model predicts an attack type, additional logic provides recommended defense actions based on the attack severity.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Setup and Installation](#setup-and-installation)
- [Usage](#usage)
  - [Training the Model](#training-the-model)
  - [Testing the Model](#testing-the-model)
  - [Transforming Datasets](#transforming-datasets)
  - [Defense Mechanisms](#defense-mechanisms)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Overview

The project has three major components:
1. **Cyber Attack Detection:**  
   Uses an XGBoost classifier (with GPU acceleration) to classify cyber attacks based on features derived from network traffic data.
2. **Data Transformation:**  
   Provides utilities to transform any dataset into the required format (i.e., using 19 specific features) for the trained model.
3. **Defense Mechanisms:**  
   Based on the predicted attack type and its severity, the system recommends a set of defense actions.

Key features (the model uses these 19 parameters):
- `proto`, `service`, `duration`, `conn_state`, `src_bytes`
- `dst_bytes`, `src_pkts`, `dst_pkts`, `src_port`, `dst_port`
- `http_status_code`, `http_trans_depth`, `dns_qtype`, `dns_rcode`
- `dns_rejected`, `ssl_established`, `ssl_resumed`, `missed_bytes`
- `weird_notice`

## Project Structure

- **detector.py**  
  Contains the `CyberAttackDetector` class which wraps the XGBoost model. The model is initialized as follows:
  ```python
  self.model = XGBClassifier(
      n_estimators=100,
      max_depth=20,
      random_state=42,
      device="cuda"  # Utilizes GPU acceleration for training
  )
  ```

- **train.py**  
  Loads the training dataset, trains the model using the specified features, and then saves the trained model to cyber_attack_model.joblib.

- **test.py**  
  Loads a dataset that follows the same format as the training data and uses the trained model to predict the type of cyber attack.

- **defense.py**  
  Contains functions that accept an attack type and its severity and then return the appropriate defense actions to mitigate the threat.

- **transform.py**  
  Provides functionality to convert any given dataset into the required format (with the 19 features) so that it can be used for testing with the trained model.

## Setup and Installation

### Prerequisites
- Python 3.6+
- A working CUDA-enabled GPU (optional but recommended for faster training)

### Installation Steps

1. Clone the Repository:
   ```bash
   git clone https://github.com/your_username/cyber-attack-detection.git
   cd cyber-attack-detection
   ```

2. Set Up a Virtual Environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Required Packages:  
   Ensure you have a requirements.txt file listing the dependencies. Then run:
   ```bash
   pip install -r requirements.txt
   ```

   If a requirements.txt file is not provided, install the following packages manually:
   ```bash
   pip install pandas numpy scikit-learn xgboost joblib seaborn matplotlib
   ```

## Usage

### Training the Model

1. Prepare Your Training Data:
   - The training dataset must include the 19 required features. If your raw dataset contains more features, use transform.py to map and filter the dataset accordingly.

2. Run the Training Script:
   ```bash
   python train.py
   ```
   This will load the training data, train the XGBoost classifier, and save the model as cyber_attack_model.joblib.

### Testing the Model

1. Prepare a Test Dataset:
   - Make sure the dataset has been transformed to include only the required features.

2. Run the Testing Script:
   ```bash
   python test.py
   ```
   This script will load cyber_attack_model.joblib and output predictions for the test dataset.

### Transforming Datasets

If your dataset does not match the expected format, use transform.py to convert it:

```bash
python transform.py --input raw_data.csv --output transformed_data.csv
```

This script applies a mapping (similar to the one below) to rename and filter the columns:

```python
parameter_mapping = {
    'Protocol type ': 'proto',
    'Service': 'service',
    'Session duration': 'duration',
    'Connection type (secure/non-secure)': 'conn_state',
    'Source bytes': 'src_bytes',
    'Destination bytes': 'dst_bytes',
    'Number of packets sent': 'src_pkts',
    'Number of packets received': 'dst_pkts',
    'Source port': 'src_port',
    'Destination port': 'dst_port',
    'HTTP response codes': 'http_status_code',
    'HTTP request patterns': 'http_trans_depth',
    'DNS queries performed': 'dns_qtype',
    'DNS query response time': 'dns_rcode',
    'Suspicious DNS responses': 'dns_rejected',
    'Secure Socket Layer (SSL) usage': 'ssl_established',
    'SSL/TLS handshake status': 'ssl_resumed',
    'Missed bytes': 'missed_bytes',
    'Weird notice': 'weird_notice'
}
```

### Defense Mechanisms

To determine the necessary actions based on the attack type and its severity, use the get_defense_actions function from defense.py:

```python
from defense import get_defense_actions

# Example usage:
attack_type = "DoS"  # Replace with the predicted attack type
severity = 5         # Severity can be defined based on your risk assessment
actions = get_defense_actions(attack_type, severity)
print("Recommended Defense Actions:", actions)
```

## Dependencies

This project uses the following Python packages:

- pandas and numpy: For data manipulation and numerical computations.
- scikit-learn: For data preprocessing, model evaluation (e.g., classification reports, confusion matrices), and train/test splitting.
- xgboost: Implements the XGBClassifier, which is used for training the detection model.
- joblib: For saving and loading the trained model.
- seaborn and matplotlib: For data visualization and analysis (optional).
- Other modules: random, json, datetime, os, and typing are used throughout the project for various utility functions.

## Contributing

Contributions are welcome! If you have suggestions or bug fixes, please follow these steps:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit and push your changes.
5. Open a pull request detailing your modifications.

For any major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For questions, suggestions, or bug reports, please contact:

Your Name  
Email: your.email@example.com

## Additional Notes

### GPU Acceleration
The XGBClassifier is set to use CUDA for GPU acceleration (device="cuda"). If you are running on a CPU-only machine, you may need to modify this parameter in detector.py.

### Data Format
Ensure that the input datasets follow the expected schema (i.e., include the 19 required features). Use the transform.py script if necessary to align your dataset with the required format.

### Model Evaluation
The project supports model evaluation through scikit-learn's classification reports and confusion matrices. You can modify train.py or test.py to include additional evaluation metrics as needed.

Enjoy using the Cyber Attack Type Detection and Defense Mechanisms Project to enhance your cybersecurity strategies!