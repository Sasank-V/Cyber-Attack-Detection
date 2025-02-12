import pandas as pd
import argparse
import sys
from typing import Dict, List
import logging

def setup_logging():
    """Configure logging for the script."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def load_dataset(file_path: str) -> pd.DataFrame:
    """
    Load the dataset from a CSV file.
    
    Args:
        file_path (str): Path to the input CSV file
    
    Returns:
        pd.DataFrame: Loaded dataset
    """
    try:
        return pd.read_csv(file_path)
    except FileNotFoundError:
        logging.error(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error loading dataset: {str(e)}")
        sys.exit(1)

def get_parameter_mapping() -> Dict[str, str]:
    """
    Define the mapping from dataset parameters to features.
    
    Returns:
        Dict[str, str]: Dictionary containing the parameter mapping
    """
    return {
        'Protocol type ': 'proto',  # String: Transport layer protocols of flow connections
        'Service': 'service',  # String: Dynamically detected protocols (DNS, HTTP, SSL)
        'Session duration': 'duration',  # Number: Time of packet connections
        'Connection type (secure/non-secure)': 'conn_state',  # String: Connection states (S0, S1, REJ)
        'Source bytes': 'src_bytes',  # Number: Source payload bytes from TCP sequence numbers
        'Destination bytes': 'dst_bytes',  # Number: Destination payload bytes from TCP sequence numbers
        'Number of packets sent': 'src_pkts',  # Number: Number of original packets from source
        'Number of packets received': 'dst_pkts',  # Number: Number of packets from destination
        'Source port': 'src_port',  # Number: Source TCP/UDP ports
        'Destination port': 'dst_port',  # Number: Destination TCP/UDP ports
        'HTTP response codes': 'http_status_code',  # Number: Status codes from HTTP server
        'HTTP request patterns': 'http_trans_depth',  # Number: Pipelined depth into HTTP connection
        'DNS queries performed': 'dns_qtype',  # Number: DNS query types
        'DNS query response time': 'dns_rcode',  # Number: Response codes in DNS responses
        'Suspicious DNS responses': 'dns_rejected',  # Boolean: DNS queries rejected by server
        'Secure Socket Layer (SSL) usage': 'ssl_established',  # Boolean: SSL connection established
        'SSL/TLS handshake status': 'ssl_resumed',  # Boolean: SSL connection resumed
        'Missed bytes': 'missed_bytes',  # Number: Number of missing bytes in content gaps
        'Weird notice': 'weird_notice'  # Boolean: Indicates violation/anomaly notices
    }

def validate_features(data: pd.DataFrame, features: List[str]) -> List[str]:
    """
    Check for missing columns in the dataset.
    
    Args:
        data (pd.DataFrame): Input dataset
        features (List[str]): List of required features
    
    Returns:
        List[str]: List of missing features
    """
    return [feature for feature in features if feature not in data.columns]

def transform_dataset(input_file: str, output_file: str) -> None:
    """
    Transform the dataset according to the required format.
    
    Args:
        input_file (str): Path to input CSV file
        output_file (str): Path to output CSV file
    """
    # Set up logging
    setup_logging()
    
    # Load the dataset
    logging.info(f"Loading dataset from {input_file}")
    data = load_dataset(input_file)
    
    # Get parameter mapping
    parameter_mapping = get_parameter_mapping()
    features_to_use = list(parameter_mapping.values())
    
    # Rename columns
    logging.info("Renaming columns based on parameter mapping")
    try:
        data.rename(columns=parameter_mapping, inplace=True)
    except Exception as e:
        logging.error(f"Error renaming columns: {str(e)}")
        sys.exit(1)
    
    # Check for missing columns
    missing_columns = validate_features(data, features_to_use)
    if missing_columns:
        logging.warning(f"The following required features are missing: {missing_columns}")
        user_input = input("Do you want to continue without these features? (y/n): ")
        if user_input.lower() != 'y':
            logging.info("Transform cancelled by user")
            sys.exit(0)
    
    # Filter dataset
    logging.info("Filtering dataset to include only specified features")
    available_features = [f for f in features_to_use if f not in missing_columns]
    filtered_data = data[available_features]
    
    # Save transformed dataset
    try:
        filtered_data.to_csv(output_file, index=False)
        logging.info(f"Transformed dataset saved successfully to {output_file}")
    except Exception as e:
        logging.error(f"Error saving transformed dataset: {str(e)}")
        sys.exit(1)

def main():
    """Main function to handle command line arguments and run the transformation."""
    parser = argparse.ArgumentParser(description='Transform cyber attack detection dataset.')
    parser.add_argument('--input', '-i', required=True, help='Input CSV file path')
    parser.add_argument('--output', '-o', required=True, help='Output CSV file path')
    
    args = parser.parse_args()
    transform_dataset(args.input, args.output)

if __name__ == "__main__":
    main()