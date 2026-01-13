import pandas as pd
import numpy as np
import glob
import os

# We define the cleaned names we want.
# The script will find the closest match regardless of leading spaces.
TARGET_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 
    'Total Backward Packets', 'Flow Bytes/s', 'Flow Packets/s', 
    'Flow IAT Mean', 'Packet Length Mean', 'Active Mean', 'Idle Mean', 'Label'
]

def preprocess_all_data(raw_dir, output_file):
    all_files = glob.glob(os.path.join(raw_dir, "*.csv"))
    if not all_files:
        print(f"❌ No CSV files found in {raw_dir}")
        return

    processed_list = []

    for file in all_files:
        print(f"Processing: {os.path.basename(file)}")
        
        # Load the first row to fix headers
        df_header = pd.read_csv(file, nrows=0)
        actual_columns = df_header.columns.tolist()
        
        # Create a mapping from "Clean Name" -> "Actual Name in CSV"
        # Example: 'Flow Bytes/s' -> ' Flow Bytes/s'
        column_mapping = {}
        for target in TARGET_COLUMNS:
            match = [c for c in actual_columns if c.strip() == target]
            if match:
                column_mapping[target] = match[0]
        
        if len(column_mapping) < len(TARGET_COLUMNS):
            missing = set(TARGET_COLUMNS) - set(column_mapping.keys())
            print(f"⚠️ Skipping {os.path.basename(file)}: Missing columns {missing}")
            continue

        # Now load only the mapped columns
        df = pd.read_csv(file, usecols=list(column_mapping.values()))
        
        # Rename columns to our clean standard names
        inv_mapping = {v: k for k, v in column_mapping.items()}
        df.rename(columns=inv_mapping, inplace=True)
        
        # 1. Clean data
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # 2. Binary Labeling
        df['Label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
        
        # 3. Balancing (Downsampling Benign)
        df_benign = df[df['Label'] == 0]
        df_attack = df[df['Label'] == 1]
        
        if len(df_benign) > len(df_attack) and len(df_attack) > 0:
            df_benign = df_benign.sample(len(df_attack), random_state=42)
        
        processed_list.append(pd.concat([df_benign, df_attack]))

    if not processed_list:
        print("❌ Final check failed: No valid data found in any CSV.")
        return

    final_df = pd.concat(processed_list, ignore_index=True)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    final_df.to_csv(output_file, index=False)
    
    print("-" * 30)
    print(f"✅ Success! Cleaned data saved to: {output_file}")
    print(f"📊 Final Dataset: {final_df.shape[0]} rows | {final_df.shape[1]} columns")

if __name__ == "__main__":
    preprocess_all_data("data/raw", "data/processed/cleaned_traffic.csv")