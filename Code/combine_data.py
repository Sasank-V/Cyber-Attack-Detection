import os
import pandas as pd

# Directory containing the CSV files
csv_folder = "../Datasets"

# Output file path
output_file = "full_network_dataset.csv"

# List to store DataFrames
data_frames = []

# Iterate through each file in the folder
for file in os.listdir(csv_folder):
    if file.endswith(".csv"):  # Check if it's a CSV file
        file_path = os.path.join(csv_folder, file)
        df = pd.read_csv(file_path)  # Read CSV into a DataFrame
        data_frames.append(df)

# Combine all DataFrames into one
combined_df = pd.concat(data_frames, ignore_index=True)

# Save the combined DataFrame to a CSV file
combined_df.to_csv(output_file, index=False)

print(f"Combined CSV file saved as {output_file}")
