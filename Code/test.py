from detector import CyberAttackDetector
import joblib
import pandas as pd
import numpy as np
from typing import Dict
import random
from defense import get_defense_actions
import json
from datetime import datetime
import os

# Replace this your own Severity Function
def get_severity_level(severity_score: float) -> str:
    #Convert severity score to level
    if severity_score >= 0.7:
        return 'high'
    elif severity_score >= 0.4:
        return 'medium'
    return 'low'

def write_to_file(detections: list, filename: str) -> None:

    with open(filename, 'w') as f:
        # Write header
        f.write("Cyber Attack Detection and Defense Report\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        
        # Write each detection
        for detection in detections:
            f.write(f"Detection #{detection['id']}\n")
            f.write(f"Attack Type: {detection['attack_type'].upper()}\n")
            f.write(f"Severity Score: {detection['severity_score']:.2f} ")
            f.write(f"({detection['severity_level'].upper()})\n\n")
            
            f.write("Defense Actions:\n")
            if detection['defense_actions']:
                for action_name, action_details in detection['defense_actions'].items():
                    f.write(f"\n{action_name}:\n")
                    for param, value in action_details.items():
                        f.write(f"  - {param}: {value}\n")
            else:
                f.write("No specific defense actions defined for this attack type/severity\n")
                
            f.write("\n" + "="*50 + "\n\n")

def process_and_defend(detector: CyberAttackDetector, data: pd.DataFrame) -> None:

    # Select only the features used by the model
    available_features = [f for f in detector.features_to_use if f in data.columns]
    X = data[available_features]
    
    # Preprocess the data
    X_processed = detector.preprocess_data(X, training=False)
    
    # Get predictions
    predictions = detector.predict(X_processed)
    
    # Create output directory if it doesn't exist
    output_dir = "detection_reports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate timestamp for filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"detection_report_{timestamp}.txt")
    
    # Store all detections
    detections = []
    
    # Process each prediction
    for i, attack_type in enumerate(predictions):
        # Getting severity here
        severity_score = random.uniform(0.1, 1.0)
        severity_level = get_severity_level(severity_score)
        
        # Get defense actions
        attack_type = attack_type.lower()
        defense_actions = get_defense_actions(attack_type, severity_level)
        
        # Store detection information
        detection = {
            'id': i + 1,
            'attack_type': attack_type,
            'severity_score': severity_score,
            'severity_level': severity_level,
            'defense_actions': defense_actions
        }
        detections.append(detection)
        
        # Print to console
        print(f"\nProcessed detection #{i+1}: {attack_type.upper()} "
              f"(Severity: {severity_score:.2f})")
    
    # Write all detections to file
    write_to_file(detections, filename)
    print(f"\nDetailed report written to: {filename}")
    
    # Also save a JSON version for programmatic access
    json_filename = os.path.join(output_dir, f"detection_report_{timestamp}.json")
    with open(json_filename, 'w') as f:
        json.dump(detections, f, indent=4)
    print(f"JSON report written to: {json_filename}")

def main():
    # Load components
    print("Loading model components...")
    try:
        model_components = joblib.load('cyber_attack_model.joblib')
        detector = model_components['detector']
        print("Model loaded successfully!")
        
        # Load your test data
        print("\nLoading test data...")
        test_data = pd.read_csv('../Datasets/training_data_sample.csv', low_memory=False) # Set your test dataset path 
        print(f"Loaded test data with shape: {test_data.shape}")
        
        # Process data and implement defense actions
        print("\nProcessing data and determining defense actions...")
        process_and_defend(detector, test_data)
        
    except FileNotFoundError as e:
        print(f"Error: Required file not found - {str(e)}")
    except Exception as e:
        print(f"Error during processing: {str(e)}")

if __name__ == "__main__":
    main()