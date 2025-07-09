import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from typing import Dict, List, Tuple, Optional
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class ThreatClassifier:
    """
    Advanced threat classification system for network packet analysis.
    Classifies network traffic into version threat categories using machine learning.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.logger = self._setup_logger()
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = None
        self.feature_names = []
        self.threat_categories = [
            'benign', 'malware', 'ddos', 'port_scan', 'intrusion', 
            'data_exfiltration', 'botnet', 'phishing', 'ransomware'
        ]

        if model_path:
            self.load_model(model_path)
        else:
            self.model = self._create_ensemble_model()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('ThreatClassifier')
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s' 
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger
    
    def _create_ensemble_model(self):
        """Create an ensemble model combining multiple classifiers"""
        from sklearn.ensemble import VotingClassifier

        # individual classifiers
        rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        gb_classifier = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42
        )

        # Ensemble voting classifier
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf_classifier),
                ('gb', gb_classifier)
            ],
            voting='soft'
        )

        return ensemble
    
    def extract_features(self, packet_data: Dict) -> np.array:
         """
        Extract relevant features from packet data for threat classification
        Args:
            packet_data: Dictionary containing packet information 
        Returns:
            numpy array of extracted features
        """
         features = []

         #basic packet features
         features.extend([
            packet_data.get('packet_size', 0),
            packet_data.get('protocol', 0),  # Encoded protocol number
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('flags', 0),
            packet_data.get('window_size', 0),
            packet_data.get('ttl', 0),
         ])

         # Flow-based features
         features.extend([
            packet_data.get('flow_duration', 0),
            packet_data.get('total_fwd_packets', 0),
            packet_data.get('total_bwd_packets', 0),
            packet_data.get('total_length_fwd_packets', 0),
            packet_data.get('total_length_bwd_packets', 0),
            packet_data.get('fwd_packet_length_max', 0),
            packet_data.get('fwd_packet_length_min', 0),
            packet_data.get('fwd_packet_length_mean', 0),
            packet_data.get('fwd_packet_length_std', 0),
            packet_data.get('bwd_packet_length_max', 0),
            packet_data.get('bwd_packet_length_min', 0),
            packet_data.get('bwd_packet_length_mean', 0),
            packet_data.get('bwd_packet_length_std', 0),
        ])
        
        # Timing features
         features.extend([
            packet_data.get('flow_bytes_per_second', 0),
            packet_data.get('flow_packets_per_second', 0),
            packet_data.get('flow_iat_mean', 0),
            packet_data.get('flow_iat_std', 0),
            packet_data.get('flow_iat_max', 0),
            packet_data.get('flow_iat_min', 0),
            packet_data.get('fwd_iat_total', 0),
            packet_data.get('fwd_iat_mean', 0),
            packet_data.get('fwd_iat_std', 0),
            packet_data.get('fwd_iat_max', 0),
            packet_data.get('fwd_iat_min', 0),
            packet_data.get('bwd_iat_total', 0),
            packet_data.get('bwd_iat_mean', 0),
            packet_data.get('bwd_iat_std', 0),
            packet_data.get('bwd_iat_max', 0),
            packet_data.get('bwd_iat_min', 0),
        ])
        
        # Protocol-specific features
         features.extend([
            packet_data.get('fwd_psh_flags', 0),
            packet_data.get('bwd_psh_flags', 0),
            packet_data.get('fwd_urg_flags', 0),
            packet_data.get('bwd_urg_flags', 0),
            packet_data.get('fwd_header_length', 0),
            packet_data.get('bwd_header_length', 0),
            packet_data.get('fwd_packets_per_second', 0),
            packet_data.get('bwd_packets_per_second', 0),
        ])
        
        # Statistical features
         features.extend([
            packet_data.get('min_packet_length', 0),
            packet_data.get('max_packet_length', 0),
            packet_data.get('packet_length_mean', 0),
            packet_data.get('packet_length_std', 0),
            packet_data.get('packet_length_variance', 0),
            packet_data.get('down_up_ratio', 0),
            packet_data.get('average_packet_size', 0),
            packet_data.get('avg_fwd_segment_size', 0),
            packet_data.get('avg_bwd_segment_size', 0),
        ])
        
        # Advanced features for specific threats
         features.extend([
            packet_data.get('subflow_fwd_packets', 0),
            packet_data.get('subflow_fwd_bytes', 0),
            packet_data.get('subflow_bwd_packets', 0),
            packet_data.get('subflow_bwd_bytes', 0),
            packet_data.get('init_win_bytes_forward', 0),
            packet_data.get('init_win_bytes_backward', 0),
            packet_data.get('act_data_pkt_fwd', 0),
            packet_data.get('min_seg_size_forward', 0),
            packet_data.get('active_mean', 0),
            packet_data.get('active_std', 0),
            packet_data.get('active_max', 0),
            packet_data.get('active_min', 0),
            packet_data.get('idle_mean', 0),
            packet_data.get('idle_std', 0),
            packet_data.get('idle_max', 0),
            packet_data.get('idle_min', 0),
        ])
         return np.array(features, dtype=np.float32)
    
    def prepare_training_data(self, dataset_path: str) -> Tuple[np.array, np.array]:
        """
        Prepare training data from dataset
        Args:
            dataset_path: Path to the training dataset   
        Returns:
            Tuple of features and labels
        """
        self.logger.info(f"Loading training data from {dataset_path}")

        # load dataset (assuming CSV format)
        df = pd.read_csv(dataset_path)

        # separate features and labels
        label_column = 'label'  # assuming label column exists

        X = df.drop(columns=[label_column])
        Y = df[label_column]

        # store features values
        self.feature_names = X.columns.tolist()

        #handle missing values
        X = X.fillna(0)

        #encode labels
        Y_encoded = self.label_encoder.fit_transform(Y)

        self.logger.info(f"Dataset loaded: {X.shape[0]} samples, {X.shape[1]} features")
        self.logger.info(f"Threat categories: {self.label_encoder.classes_}")

        return X.values, Y_encoded
    
    def train_model(self, X: np.array, Y: np.array, test_size: float = 0.2):
        """
        Train the threat classification model
        Args:
            X: Feature matrix
            y: Target labels
            test_size: Fraction of data to use for testing
        """

        self.logger.info("Starting model training...")

        # split data
        X_train, X_test, Y_train, Y_test = train_test_split(
            X, Y, test_size=test_size, random_state=42, stratify=Y
        )

        # scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # train model
        self.model.fit(X_train_scaled, Y_train)

        # evaluate model
        train_score = self.model.score(X_train_scaled, Y_train)
        test_score = self.model.score(X_test_scaled, Y_test)

        self.logger.info(f"Training accuracy: {train_score:.4f}")
        self.logger.info(f"Test accuracy: {test_score:.4f}")

        # detailed evaluation
        Y_pred = self.model.predict(X_test_scaled)

        self.logger.info("\nClassification Report:")
        self.logger.info(classification_report(
            Y_test, Y_pred,
            target_names=self.label_encoder.classes_
        ))

        return {
            'train_accuracy': train_score,
            'test_accuracy': test_score,
            'model': self.model,
            'scaler': self.scaler
        }
    
    def predict_threat(self, packet_data: Dict) -> Dict:
        """
        Predict threat category for a single packet
        Args:
            packet_data: Dictionary containing packet information   
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        # Extract features
        features = self.extract_features(packet_data)
        
        # Reshape for prediction
        features = features.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        # Get threat category
        threat_category = self.label_encoder.inverse_transform([prediction])[0]
        
        # Create probability dictionary
        prob_dict = {}
        for i, category in enumerate(self.label_encoder.classes_):
            prob_dict[category] = float(probabilities[i])
        
        result = {
            'threat_category': threat_category,
            'confidence': float(max(probabilities)),
            'probabilities': prob_dict,
            'timestamp': datetime.now().isoformat(),
            'is_malicious': threat_category != 'benign'
        }
        
        return result
    
    def predict_batch(self, packet_batch: List[Dict]) -> List[Dict]:
        """
        Predict threats for a batch of packets
        Args:
            packet_batch: List of packet data dictionaries   
        Returns:
            List of prediction results
        """
        results = []

        for packet_data in packet_batch:
            try:
                result = self.predict_threat(packet_data)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error predicting threat: {e}")
                results.append({
                    'threat_category': 'unknown',
                    'confidence': 0.0,
                    'error': str(e)
                })
        return results
    
    def get_threat_statistics(self, predictions: List[Dict]) -> Dict:
        """
        Generate statistics from threat predictions
        Args:
            predictions: List of prediction results 
        Returns:
            Dictionary with threat statistics
        """
        total_packets = len(predictions)

        if total_packets == 0:
            return {'total_packets': 0}
        
        # count threats
        threat_counts = {}
        malicious_count = 0

        for pred in predictions:
            category = pred.get('threat_categoey', 'unknown')
            threat_counts[category] = threat_counts.get(category, 0) + 1

            if pred.get('is_malicious', False):
                malicious_count += 1
        
        # calculate percentages
        threat_percentages = {}
        for category, count in threat_counts.items():
            threat_percentages[category] = (count / total_packets) * 100

        return {
            'total_packets': total_packets,
            'malicious_packets': malicious_count,
            'benign_packets': total_packets - malicious_count,
            'malicious_percentage': (malicious_count / total_packets) * 100,
            'threat_counts': threat_counts,
            'threat_percentages': threat_percentages
        }
    
    def save_model(self, model_path: str):
        """Save the trained model and preprocessors"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'threat_categories': self.threat_categories,
        }

        joblib.dump(model_data, model_path)
        self.logger.info(f"Model saved to {model_path}")

    def load_model(self, model_path: str):
        """Load a trained model and preprocessors"""
        try:
            model_data = joblib.load(model_path)

            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.feature_names = model_data['feature_names']
            self.threat_categories = model_data['threat_categories']

            self.logger.info(f"Model loaded from {model_path}")

        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise

    def update_model(self, new_data: List[Dict], new_labels: List[str]):
        """
        Update the model with new training data (online learning)
        Args: new_data: List of new packet data
              new_labels: List of corresponding labels
        """

        if self.model is None:
            raise ValueError("Model not initialized")
        
        # extract features from new data
        X_new = []
        for packet in new_data:
            features = self.extract_features(packet)
            X_new.append(features)

        X_new = np.array(X_new)

        # encode new labels
        Y_new = self.label_encoder.transforn(new_labels)

        # scale new features
        X_new_scaled = self.scaler.transform(X_new)

        # update model (if supported)
        if hasattr(self.model, 'partial_fit'):
            self.model.partial_fit(X_new_scaled, Y_new)
        else:
            self.logger.warning("Model doesn't support online learning")
        
        self.logger.info(f"Model updated with {len(new_data)} new samples")

# example usage and testing
if __name__ == "__main__":
    # initialize classifier
    classifier = ThreatClassifier()

    # example packet data 
    sample_packet = {
        'packet_size': 1500,
        'protocol': 6,       # tcp
        'src_port': 443,
        'dst_port': 8080,
        'flags': 24,
        'window_size': 65535,
        'ttl': 64,
        'flow_duration': 1000,
        'total_fwd_packets': 10,
        'total_bwd_packets': 8,
        'total_length_fwd_packets': 15000,
        'total_length_bwd_packets': 12000,
        'fwd_packet_length_max': 1500,
        'fwd_packet_length_min': 60,
        'fwd_packet_length_mean': 1500,
        'fwd_packet_length_std': 100,
        'bwd_packet_length_max': 1500,
        'bwd_packet_length_min': 60,
        'bwd_packet_length_mean': 1500,
        'bwd_packet_length_std': 100,
        'flow_bytes_per_second': 27000,
        'flow_packets_per_second': 18,
        'flow_iat_mean': 100,
        'flow_iat_std': 50,
        'flow_iat_max': 200,
        'flow_iat_min': 50
    }

    # Note: For actual usage, you would need to:
    # 1. Load and prepare training data
    # 2. Train the model
    # 3. Save the trained model
    # 4. Load the model for inference
    
    print("Threat Classification System initialized")
    print("Features extracted from sample packet:", len(classifier.extract_features(sample_packet)))



    
