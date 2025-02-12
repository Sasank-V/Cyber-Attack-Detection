# train.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import seaborn as sns
import matplotlib.pyplot as plt
import joblib
from detector import CyberAttackDetector

def main():
    # Load dataset
    print("Loading the dataset...")
    combined_file_path = '../Datasets/full_network_dataset.csv'
    df = pd.read_csv(combined_file_path, low_memory=False)
    print(f"Dataset loaded: {df.shape[0]} rows and {df.shape[1]} columns")
    
    # Initialize detector
    detector = CyberAttackDetector()
    
    # Prepare features and target
    X = df[df.columns.intersection(detector.features_to_use)]
    y = df['type']
    
    # Split data
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Preprocess data
    print("Preprocessing data...")
    X_train_processed = detector.preprocess_data(X_train, training=True)
    X_test_processed = detector.preprocess_data(X_test, training=False)
    
    # Train model
    print("Training model...")
    detector.train(X_train_processed, y_train)
    
    # Evaluate model
    print("Evaluating model...")
    report, cm, predictions = detector.evaluate(X_test_processed, y_test)
    print("\nClassification Report:")
    print(report)
    
    # Plot confusion matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    plt.close()
    
    # Feature importance 
    feature_importance = pd.DataFrame({
        'feature': X_train_processed.columns,
        'importance': detector.model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))
    
    # Save the model and important components
    print("\nSaving model and components...")
    model_components = {
        'detector': detector,
        'feature_importance': feature_importance,
        'training_report': report
    }
    joblib.dump(model_components, 'cyber_attack_model.joblib')
    print("Model and components saved as 'cyber_attack_model.joblib'")

if __name__ == "__main__":
    main()