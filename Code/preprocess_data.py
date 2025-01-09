import pandas as pd
from train import CyberAttackDetector

input_file = '../Datasets/full_network_dataset.csv'
df = pd.read_csv(input_file)

# Preprocess the data
print("Initialising Detector...")
detector = CyberAttackDetector()
print("Preprocessing the dataset...")
processed_df = detector.preprocess_data(df, training=True)

# Save the preprocessed data to a new file
output_file = '../Datasets/preprocessed_network_dataset.csv'
processed_df.to_csv(output_file, index=False)
print(f"Preprocessed data saved to {output_file}")