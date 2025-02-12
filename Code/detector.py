# detector.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, confusion_matrix

class CyberAttackDetector:
    def __init__(self):
        self.target_encoder = LabelEncoder()
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            device="cuda"  # Used GPU for training
        )
        # Refined feature set
        self.features_to_use = [
            'proto', 'service', 'duration', 'conn_state', 'src_bytes',
            'dst_bytes', 'src_pkts', 'dst_pkts', 'src_port', 'dst_port',
            'http_status_code', 'http_trans_depth', 'dns_qtype', 'dns_rcode',
            'dns_rejected', 'ssl_established', 'ssl_resumed', 'missed_bytes',
            'weird_notice'
        ]
        
        self.numeric_columns = [
            'src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes',
            'missed_bytes', 'src_pkts', 'dst_pkts', 'dns_qtype', 'dns_rcode',
            'http_trans_depth', 'http_status_code'
        ]
        
        self.categorical_features = ['proto', 'service', 'conn_state']
        self.boolean_features = ['dns_rejected', 'ssl_resumed', 'ssl_established', 'weird_notice']
    
    def preprocess_data(self, df, training=True):
        df_processed = df.copy()
        
        # Keep only selected features
        available_features = [f for f in self.features_to_use if f in df_processed.columns]
        df_processed = df_processed[available_features]
        
        # Convert numeric columns
        for col in self.numeric_columns:
            if col in df_processed.columns:
                df_processed[col] = df_processed[col].replace('-', '0')
                df_processed[col] = pd.to_numeric(df_processed[col], errors='coerce').fillna(0)
        
        # Convert boolean features
        bool_map = {
            'F': 0, 'T': 1,
            'false': 0, 'true': 1,
            'FALSE': 0, 'TRUE': 1,
            '-': 0, '': 0,
            False: 0, True: 1
        }
        for col in self.boolean_features:
            if col in df_processed.columns:
                df_processed[col] = df_processed[col].map(bool_map).fillna(0).astype(int)
        
        # Encode categorical features
        for feature in self.categorical_features:
            if feature in df_processed.columns:
                df_processed[feature] = df_processed[feature].replace(['-', ''], 'unknown')
                df_processed[feature] = df_processed[feature].fillna('unknown')
                
                if training:
                    self.label_encoders[feature] = LabelEncoder()
                    unique_values = list(set(df_processed[feature].unique().tolist() + ['unknown']))
                    self.label_encoders[feature].fit(unique_values)
                
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

        y_train_encoded = self.target_encoder.fit_transform(y_train)
        self.model.fit(X_train, y_train_encoded)
    
    def predict(self, X):

        predictions_encoded = self.model.predict(X)
        return self.target_encoder.inverse_transform(predictions_encoded)
    
    def evaluate(self, X_test, y_test):

        predictions = self.predict(X_test)
        report = classification_report(y_test, predictions)
        cm = confusion_matrix(y_test, predictions)
        return report, cm, predictions