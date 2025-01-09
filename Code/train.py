import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder

class CyberAttackDetector:
    def __init__(self):
        self.target_encoder = LabelEncoder()
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            device="cuda"  # Use GPU for training
        )
        # Refined feature set
        self.features_to_use = [
            'proto',
            'service',
            'duration',
            'conn_state',
            'src_bytes',
            'dst_bytes',
            'src_pkts',
            'dst_pkts',
            'src_port',
            'dst_port',
            'http_status_code',
            'http_trans_depth',
            'dns_qtype',
            'dns_rcode',
            'dns_rejected',
            'ssl_established',
            'ssl_resumed',
            'missed_bytes',
            'weird_notice'
        ]
    
    def preprocess_data(self, df, training=True):
        """Preprocess the data with improved handling of missing and unseen values"""
        df_processed = df.copy()
        
        # Keep only selected features
        available_features = [f for f in self.features_to_use if f in df_processed.columns]
        df_processed = df_processed[available_features]
        
        # Convert numeric columns to float, replacing '-' with 0
        numeric_columns = [
            'src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes',
            'missed_bytes', 'src_pkts', 'dst_pkts', 'dns_qtype', 'dns_rcode',
            'http_trans_depth', 'http_status_code'
        ]
        
        for col in numeric_columns:
            if col in df_processed.columns:
                df_processed[col] = df_processed[col].replace('-', '0')
                df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0)
        
        # Handle categorical features
        categorical_features = ['proto', 'service', 'conn_state']
        
        # Handle boolean features
        boolean_features = ['dns_rejected', 'ssl_resumed', 'ssl_established', 'weird_notice']
        
        # Convert boolean features
        for col in boolean_features:
            if col in df_processed.columns:
                # Map various boolean representations to 0/1
                bool_map = {
                    'F': 0, 'T': 1,
                    'false': 0, 'true': 1,
                    'FALSE': 0, 'TRUE': 1,
                    '-': 0, '': 0,
                    False: 0, True: 1
                }
                df_processed[col] = df_processed[col].map(bool_map).fillna(0).astype(int)
        
        # Encode categorical features with improved handling of unseen categories
        for feature in categorical_features:
            if feature in df_processed.columns:
                # Replace missing values and empty strings with 'unknown'
                df_processed[feature] = df_processed[feature].replace(['-', ''], 'unknown')
                df_processed[feature] = df_processed[feature].fillna('unknown')
                
                if training:
                    # During training, fit the encoder and transform
                    self.label_encoders[feature] = LabelEncoder()
                    # Add 'unknown' to the training data to handle unseen values in test
                    unique_values = df_processed[feature].unique().tolist()
                    if 'unknown' not in unique_values:
                        unique_values.append('unknown')
                    self.label_encoders[feature].fit(unique_values)
                    df_processed[feature] = self.label_encoders[feature].transform(df_processed[feature])
                else:
                    # During testing, handle unseen categories
                    df_processed[feature] = df_processed[feature].map(
                        lambda x: 'unknown' if x not in self.label_encoders[feature].classes_ else x
                    )
                    df_processed[feature] = self.label_encoders[feature].transform(df_processed[feature])
        
        # Scale numerical features
        numerical_features = df_processed.select_dtypes(include=['int64', 'float64']).columns
        if training:
            self.scaler.fit(df_processed[numerical_features])
        df_processed[numerical_features] = self.scaler.transform(df_processed[numerical_features])
        
        return df_processed
    
    def train(self, X_train, y_train):
        """Train the Random Forest model"""
        # Encode the target variable into numeric values
        y_train_encoded = self.target_encoder.fit_transform(y_train)
        self.model.fit(X_train, y_train_encoded)
    
    def predict(self, X):
        """Make predictions using the trained model"""
        predictions_encoded = self.model.predict(X)
        # Decode the numeric predictions back to original class labels
        predictions = self.target_encoder.inverse_transform(predictions_encoded)
        return predictions
    
    def evaluate(self, X_test, y_test):
        """Evaluate the model and return performance metrics"""
        predictions = self.predict(X_test)
        report = classification_report(y_test, predictions)
        cm = confusion_matrix(y_test, predictions)
        return report, cm, predictions

def main():
   # Path to the combined dataset
    combined_file_path = '../Datasets/full_network_dataset.csv'

    # Load the combined dataset
    print("Loading the combined dataset...")
    df = pd.read_csv(combined_file_path, low_memory=False)

    # Check the combined dataset size
    print(f"Combined dataset contains {df.shape[0]} rows and {df.shape[1]} columns.")
    
    # Split features and target
    X = df[df.columns.intersection(CyberAttackDetector().features_to_use)]
    y = df['type']
    
    # Split into training and testing sets
    print("Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Initialize detector
    print("Initializing detector...")
    detector = CyberAttackDetector()
    
    # Preprocess and train
    print("Preprocessing training data...")
    X_train_processed = detector.preprocess_data(X_train, training=True)
    print("Preprocessing test data...")
    X_test_processed = detector.preprocess_data(X_test, training=False)
    
    # Train model
    print("Training model...")
    detector.train(X_train_processed, y_train)
    
    # Evaluate model
    print("Evaluating model...")
    report, cm, predictions = detector.evaluate(X_test_processed, y_test)
    
    # Print results
    print("\nClassification Report:")
    print(report)
    
    # Plot confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.show()
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X_train_processed.columns,
        'importance': detector.model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save the model
    import joblib
    joblib.dump(detector, 'cyber_attack_detector.joblib')
    print("\nModel saved as 'cyber_attack_detector.joblib'")

if __name__ == "__main__":
    main()