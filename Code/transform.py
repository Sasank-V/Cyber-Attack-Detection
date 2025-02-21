import pandas as pd
from typing import Dict

def get_parameter_mapping() -> Dict[str, str]:
    # Mapping original dataset column names to required feature names
    return {
        'Protocol type ': 'proto',  # String: Transport layer protocol (TCP, UDP, etc.)
        'Service': 'service',  # String: Application-level service (HTTP, FTP, etc.)
        'Session duration': 'duration',  # Number: Connection duration in seconds
        'Connection type (secure/non-secure)': 'conn_state',  # String: Connection state (S0, S1, REJ, etc.)
        'Source bytes': 'src_bytes',  # Number: Bytes sent from source
        'Destination bytes': 'dst_bytes',  # Number: Bytes received by destination
        'Number of packets sent': 'src_pkts',  # Number: Packets sent from source
        'Number of packets received': 'dst_pkts',  # Number: Packets received at destination
        'Source port': 'src_port',  # Number: Source port (TCP/UDP)
        'Destination port': 'dst_port',  # Number: Destination port (TCP/UDP)
        'HTTP response codes': 'http_status_code',  # Number: HTTP response status code (e.g., 200, 404)
        'HTTP request patterns': 'http_trans_depth',  # Number: HTTP connection depth (pipelined requests)
        'DNS queries performed': 'dns_qtype',  # Number: Type of DNS queries made
        'DNS query response time': 'dns_rcode',  # Number: Response code in DNS replies
        'Suspicious DNS responses': 'dns_rejected',  # Boolean: Whether the DNS query was rejected
        'Secure Socket Layer (SSL) usage': 'ssl_established',  # Boolean: Whether SSL was established
        'SSL/TLS handshake status': 'ssl_resumed',  # Boolean: Whether SSL session was resumed
        'Missed bytes': 'missed_bytes',  # Number: Count of missing bytes due to network issues
        'Weird notice': 'weird_notice'  # Boolean: Whether an anomaly was detected in the network traffic
    }

def transform_real_time_data(input_data: Dict[str, any]) -> pd.DataFrame:
    """
    Transforms a real-time network traffic data record into a standardized format for analysis.

    Args:
        input_data (Dict[str, any]): A dictionary containing network traffic details.

    Returns:
        pd.DataFrame: A DataFrame containing the transformed data with mapped column names.
    """
    
    # Load parameter mapping
    parameter_mapping = get_parameter_mapping()
    
    # Rename input data keys using mapping
    transformed_data = {
        parameter_mapping[key]: value for key, value in input_data.items() if key in parameter_mapping
    }
    
    # Convert transformed data into a DataFrame (for model prediction or storage)
    return pd.DataFrame([transformed_data])

# Example real-time input data
real_time_input = {
    "Protocol type ": "TCP",
    "Service": "HTTP",
    "Session duration": 30,
    "Connection type (secure/non-secure)": "S1",
    "Source bytes": 200,
    "Destination bytes": 150,
    "Number of packets sent": 5,
    "Number of packets received": 3,
    "Source port": 443,
    "Destination port": 8080,
    "HTTP response codes": 200,
    "HTTP request patterns": 2,
    "DNS queries performed": 1,
    "DNS query response time": 100,
    "Suspicious DNS responses": False,
    "Secure Socket Layer (SSL) usage": True,
    "SSL/TLS handshake status": False,
    "Missed bytes": 0,
    "Weird notice": False
}

# Transform and print the real-time data
transformed_df = transform_real_time_data(real_time_input)
print(transformed_df)
