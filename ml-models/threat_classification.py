import numpy as np
import pandas as pd
import numpy.typing as npt

from sklearn.ensemble import VotingClassifier, RandomForestClassifier, GradientBoostingClassifier
from sklearn.base import BaseEstimator
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from typing import Dict, List, Tuple, Optional, Union, Any
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Common fixes for sklearn/numpy issues
import sys
import os

class ThreatClassifier:
    """
    Advanced threat classification system for network packet analysis.
    Classifies network traffic into various threat categories using machine learning.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.logger = self._setup_logger()
        self.scaler = Optional[StandardScaler] = StandardScaler()
        self.label_encoder: LabelEncoder = LabelEncoder()
        self.model = Optional[Union[VotingClassifier, RandomForestClassifier, BaseEstimator]] = None
        self.feature_names: List[str] = []
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
        
        # Individual classifiers
        rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # gb_classifier = GradientBoostingClassifier(
        #     n_estimators=100,
        #     max_depth=6,
        #     random_state=42
        # )
        
        # Ensemble voting classifier
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf_classifier),
                # ('gb', gb_classifier)
            ],
            voting='soft'
        )
        
        return ensemble
    
    def extract_features(self, packet_data: Dict) -> np.ndarray:
        """
        Extract relevant features from packet data for threat classification
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            numpy array of extracted features
        """
        features = []
        
        # Basic packet features
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
        
        # Convert to numpy array with proper dtype and handle NaN/inf values
        features_array = np.array(features, dtype=np.float32)
        # Handle NaN and infinite values
        features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
        
        # # Ensure all values are finite
        # if not np.all(np.isfinite(features_array)):
        #     self.logger.warning("Non-finite values detected in features, replacing with 0")
        #     features_array = np.where(np.isfinite(features_array), features_array, 0.0)
        
        return features_array
    
    def prepare_training_data(self, dataset_path: str) -> Tuple[npt.NDArray[np.float32], npt.NDArray[np.int32]]:
        """
        Prepare training data from dataset
        Args:
            dataset_path: Path to the training dataset   
        Returns:
            Tuple of features and labels
        """
        self.logger.info(f"Loading training data from {dataset_path}")
        
        try:
            # Check if file exists
            if not os.path.exists(dataset_path):
                raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
            
            # Load dataset (assuming CSV format)
            df = pd.read_csv(dataset_path)
            self.logger.info(f"Raw dataset shape: {df.shape}")
            
            # Check if dataset is empty
            if df.empty:
                raise ValueError("Dataset is empty")
            
            # Debug: Print column names
            self.logger.info(f"Dataset columns: {df.columns.tolist()}")
            
            # Find label column (flexible naming)
            label_column = None
            possible_labels = ['label', 'Label', 'LABEL', 'target', 'Target', 'class', 'Class', 'attack_type', 'category']
            
            for col in possible_labels:
                if col in df.columns:
                    label_column = col
                    break
            
            if label_column is None:
                # If no standard label column found, use the last column
                label_column = df.columns[-1]
                self.logger.warning(f"No standard label column found, using last column: {label_column}")
            
            self.logger.info(f"Using label column: {label_column}")
            
            # Separate features and labels
            X = df.drop(columns=[label_column])
            y = df[label_column]
            
            self.logger.info(f"Features shape: {X.shape}")
            self.logger.info(f"Labels shape: {y.shape}")
            self.logger.info(f"Unique labels: {y.unique()}")
            
            # Store feature names
            self.feature_names = X.columns.tolist()
            
            # Handle missing values and data types
            self.logger.info("Cleaning feature data...")
            
            # Remove non-numeric columns except for specific ones we can encode
            numeric_cols = []
            for col in X.columns:
                if X[col].dtype in ['int64', 'float64', 'int32', 'float32']:
                    numeric_cols.append(col)
                else:
                    # Try to convert to numeric
                    try:
                        X[col] = pd.to_numeric(X[col], errors='coerce')
                        numeric_cols.append(col)
                    except:
                        self.logger.warning(f"Dropping non-numeric column: {col}")
            
            # Keep only numeric columns
            X = X[numeric_cols]
            
            # Handle missing values
            X = X.fillna(0)
            
            # Handle infinite values
            X = X.replace([np.inf, -np.inf], 0)
            
            # Clean labels
            self.logger.info("Cleaning label data...")
            
            # Remove rows with missing labels
            valid_indices = y.notna()
            X = X[valid_indices]
            y = y[valid_indices]
            
            # Convert labels to string for consistency
            y = y.astype(str).str.strip().str.lower()
            
            # Remove empty or invalid labels
            valid_labels = y != ''
            X = X[valid_labels]
            y = y[valid_labels]
            
            # Reset indices
            X = X.reset_index(drop=True)
            y = y.reset_index(drop=True)
            
            self.logger.info(f"After cleaning - Features: {X.shape}, Labels: {y.shape}")
            
            # Convert to numpy arrays
            X_array = X.values.astype(np.float32)
            
            # Handle any remaining NaN or inf values
            X_array = np.nan_to_num(X_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Initialize and fit label encoder
            self.logger.info("Encoding labels...")
            
            # Ensure we have valid labels
            if len(y) == 0:
                raise ValueError("No valid labels found after cleaning")
            
            # Fit label encoder
            try:
                y_encoded = self.label_encoder.fit_transform(y)
                self.logger.info(f"Label encoding successful. Classes: {self.label_encoder.classes_}")
            except Exception as e:
                self.logger.error(f"Label encoding failed: {e}")
                raise ValueError(f"Failed to encode labels: {e}")
            
            # Final validation
            if X_array.shape[0] != len(y_encoded):
                raise ValueError(f"Shape mismatch: X={X_array.shape[0]}, y={len(y_encoded)}")
            
            if X_array.shape[0] == 0:
                raise ValueError("No valid samples found in dataset")
            
            if X_array.shape[1] == 0:
                raise ValueError("No valid features found in dataset")
            
            self.logger.info(f"Final dataset: {X_array.shape[0]} samples, {X_array.shape[1]} features")
            self.logger.info(f"Threat categories: {self.label_encoder.classes_}")
            self.logger.info(f"Label distribution: {np.bincount(y_encoded)}")
            
            return X_array.astype(np.float32), y_encoded.astype(np.int32)
            
        except Exception as e:
            self.logger.error(f"Error preparing training data: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def train_model(self, X: npt.NDArray[np.float32], y: npt.NDArray[np.int32], test_size: float = 0.2):
        """
        Train the threat classification model
        
        Args:
            X: Feature matrix
            y: Target labels
            test_size: Fraction of data to use for testing
        """
        self.logger.info("Starting model training...")
        
        try:
            # Validate input data
            if X is None or y is None:
                raise ValueError("X and y cannot be None")
            
            if not isinstance(X, np.ndarray):
                X = np.array(X, dtype=np.float32)
            
            if not isinstance(y, np.ndarray):
                y = np.array(y)
            
            if X.shape[0] == 0 or len(y) == 0:
                raise ValueError("Empty training data")
            
            if X.shape[0] != len(y):
                raise ValueError(f"Feature matrix and labels have different lengths: X={X.shape[0]}, y={len(y)}")
            
            if X.shape[1] == 0:
                raise ValueError("No features in training data")
            
            self.logger.info(f"Training data shape: X={X.shape}, y={y.shape}")
            
            # Check for valid numeric data
            if not np.all(np.isfinite(X)):
                self.logger.warning("Non-finite values in features, cleaning data")
                X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Check for constant features (all same value)
            constant_features = []
            for i in range(X.shape[1]):
                if np.all(X[:, i] == X[0, i]):
                    constant_features.append(i)
            
            if constant_features:
                self.logger.warning(f"Found {len(constant_features)} constant features")
                # Remove constant features
                X = np.delete(X, constant_features, axis=1)
                if hasattr(self, 'feature_names') and self.feature_names:
                    self.feature_names = [name for i, name in enumerate(self.feature_names) if i not in constant_features]
            
            # Ensure minimum samples for splitting
            min_samples = max(10, len(np.unique(y)) * 2)  # At least 2 samples per class
            if X.shape[0] < min_samples:
                self.logger.warning(f"Very small dataset ({X.shape[0]} samples), consider using more data")
                test_size = 0.1  # Use smaller test size
            
            # Check class distribution
            unique_classes, class_counts = np.unique(y, return_counts=True)
            self.logger.info(f"Class distribution: {dict(zip(unique_classes, class_counts))}")
            
            # Ensure each class has at least 2 samples for stratified split
            min_class_count = min(class_counts)
            if min_class_count < 2:
                self.logger.warning("Some classes have only 1 sample, using random split instead of stratified")
                stratify = None
            else:
                stratify = y
            
            # Split data
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42, stratify=stratify
                )
                self.logger.info(f"Data split: train={X_train.shape[0]}, test={X_test.shape[0]}")
            except Exception as e:
                self.logger.warning(f"Stratified split failed: {e}, using random split")
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42
                )
            
            # Initialize scaler if not already done
            if self.scaler is None:
                self.scaler = StandardScaler()
            
            # Scale features
            try:
                self.logger.info("Scaling features...")
                X_train_scaled = self.scaler.fit_transform(X_train)
                X_test_scaled = self.scaler.transform(X_test)
                
                # Check for scaling issues
                if not np.all(np.isfinite(X_train_scaled)) or not np.all(np.isfinite(X_test_scaled)):
                   raise ValueError("Scaling produced non-finite values")
                
            except Exception as e:
                self.logger.error(f"Error in feature scaling: {e}")
                # Fallback to robust scaler
                from sklearn.preprocessing import RobustScaler
                self.scaler = RobustScaler()
                try:
                    X_train_scaled = self.scaler.fit_transform(X_train)
                    X_test_scaled = self.scaler.transform(X_test)
                except Exception as e:
                    self.logger.warning(f"Robust scaling alos failed: {e}, using original features")
                    X_train_scaled = X_train
                    X_test_scaled = X_test
                    self.scaler = None
            
            # Initialize model if not already done
            if not hasattr(self, 'model') or self.model is None:
                self.model = self._create_ensemble_model()
            
            # Train model
            self.logger.info("Training model...")
            try:
                self.model.fit(X_train_scaled, y_train)
                self.logger.info("Model training completed successfully")
            except Exception as e:
                self.logger.error(f"Model training failed: {e}")
                # Try with simpler model
                self.logger.info("Trying with simpler Random Forest model...")
                from sklearn.ensemble import RandomForestClassifier
                self.model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
                self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            try:
                train_score = self.model.score(X_train_scaled, y_train)
                test_score = self.model.score(X_test_scaled, y_test)
                
                self.logger.info(f"Training accuracy: {train_score:.4f}")
                self.logger.info(f"Test accuracy: {test_score:.4f}")
                
                # Detailed evaluation
                y_pred = self.model.predict(X_test_scaled)
                
                # Get class names for report
                if hasattr(self, 'label_encoder') and self.label_encoder is not None:
                    target_names = self.label_encoder.classes_
                else:
                    target_names = [str(i) for i in unique_classes]
                
                self.logger.info("\nClassification Report:")
                report = classification_report(
                    y_test, y_pred, 
                    target_names=target_names,
                    zero_division=0,
                    output_dict=False
                )
                self.logger.info(report)
                
                return {
                    'train_accuracy': train_score,
                    'test_accuracy': test_score,
                    'model': self.model,
                    'scaler': self.scaler,
                    'feature_count': X_train_scaled.shape[1],
                    'sample_count': X_train_scaled.shape[0],
                    'classes': unique_classes.tolist()
                }
                
            except Exception as e:
                self.logger.warning(f"Could not generate full evaluation: {e}")
                return {
                    'train_accuracy': 0.0,
                    'test_accuracy': 0.0,
                    'model': self.model,
                    'scaler': self.scaler,
                    'error': str(e)
                }
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
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
        
        try:
            # Extract features
            features = self.extract_features(packet_data)
            
            # Validate features
            if not np.all(np.isfinite(features)):
                self.logger.warning("Non-finite values in features")
                features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Reshape for prediction
            features = features.reshape(1, -1)
            
            # Scale features
            if self.scaler is not None:
                try:
                    features_scaled = self.scaler.transform(features)
                except Exception as e:
                    self.logger.warning(f"Error scaling features: {e}, using original features")
                    features_scaled = features
            else:
                features_scaled = features

            if self.model is None:
                raise ValueError("Model is None")
            
            prediction_array = self.model.predict(features_scaled)
            prediction = int(prediction_array[0]) if hasattr(prediction_array, '__getitem__') else int(prediction_array)
            
            # Get probabilities if available
            probabilities = np.zeros(len(self.label_encoder.classes_))
            if hasattr(self.model, 'predict_proba'):
                try:
                    probabilities = self.model.predict_proba(features_scaled)[0]
                except:
                    self.logger.warning(f"Could not get probabilities: {e}")
                    probabilities[prediction] = 1.0
            else:
                probabilities[prediction] = 1.0
            
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
            
        except Exception as e:
            self.logger.error(f"Error predicting threat: {e}")
            return {
                'threat_category': 'unknown',
                'confidence': 0.0,
                'probabilities': {},
                'timestamp': datetime.now().isoformat(),
                'is_malicious': False,
                'error': str(e)
            }
    
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
        
        # Count threats
        threat_counts = {}
        malicious_count = 0
        
        for pred in predictions:
            category = pred.get('threat_category', 'unknown')
            threat_counts[category] = threat_counts.get(category, 0) + 1
            
            if pred.get('is_malicious', False):
                malicious_count += 1
        
        # Calculate percentages
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
        try:
            # Ensure model is trained
            if self.model is None:
                raise ValueError("No model to save")
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'feature_names': self.feature_names,
                'threat_categories': self.threat_categories
            }
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            joblib.dump(model_data, model_path)
            self.logger.info(f"Model saved to {model_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            raise
    
    def load_model(self, model_path: str):
        """Load a trained model and preprocessors"""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
            
            model_data = joblib.load(model_path)
            
            # Validate loaded data
            required_keys = ['model', 'scaler', 'label_encoder', 'feature_names', 'threat_categories']
            for key in required_keys:
                if key not in model_data:
                    raise ValueError(f"Missing required key in model file: {key}")
            
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
        
        Args:
            new_data: List of new packet data
            new_labels: List of corresponding labels
        """
        if self.model is None:
            raise ValueError("Model not initialized")
        
        try:
            # Validate input
            if len(new_data) != len(new_labels):
                raise ValueError("Data and labels must have same length")
            
            if len(new_data) == 0:
                self.logger.warning("No new data provided")
                return
            
            # Extract features from new data
            X_new = []
            for packet in new_data:
                features = self.extract_features(packet)
                X_new.append(features)
            
            X_new = np.array(X_new)
            
            # Handle new labels - check if they exist in current encoder
            try:
                y_new = self.label_encoder.transform(new_labels)
            except ValueError as e:
                self.logger.warning(f"New labels found, refitting encoder: {e}")
                # Refit encoder with all labels
                all_labels = list(self.label_encoder.classes_) + new_labels
                self.label_encoder.fit(all_labels)
                y_new = self.label_encoder.transform(new_labels)
            
            # Scale new features
            if self.scaler is not None:
                try:
                    X_new_scaled = self.scaler.transform(X_new)
                except Exception as e:
                    self.logger.warning(f"Error scaling new features: {e}")
                    X_new_scaled = X_new
            else:
                X_new_scaled = X_new
            
            # Update model (if supported)
            if (hasattr(self.model, 'partial_fit') and callable(getattr(self.model, 'partial_fit', None))):
                self.model.partial_fit(X_new_scaled, y_new)
                self.logger.info(f"Model updated with {len(new_data)} new samples")
            else:
                self.logger.warning("Model doesn't support online learning (partial_fit)")
                
        except Exception as e:
            self.logger.error(f"Error updating model: {e}")
            raise

    def validate_model_state(classifier: ThreatClassifier) -> bool:
        """Validate that classifier is in a valid state for prediction"""
        if classifier.model is None:
            return False
        if classifier.label_encoder is None:
            return False
        if not hasattr(classifier.label_encoder, 'classes_'):
            return False
        return True
    
    def safe_predict(classifier: ThreatClassifier, packet_data: Dict) -> Dict:
        """Safe wrapper for prediction that handles all edges cases"""
        if not validate_model_state(classifier):
            return {
                'threat_category': 'unknown',
                'confidence': 0.0,
                'probabilities': {},
                'timestamp': datetime.now().isoformat(),
                'is_malicious': False,
                'error': 'Model not in valid state'
            }
        return classifier.predict_threat(packet_data)

# Example usage and testing
if __name__ == "__main__":
    # Initialize classifier
    classifier = ThreatClassifier()
    
    # Create sample training data (since we don't have a real dataset)
    print("Creating sample training data...")
    
    # Generate synthetic training data
    np.random.seed(42)
    n_samples = 1000
    n_features = 65  # Match the number of features we extract
    
    # Create synthetic features
    X_synthetic = np.random.rand(n_samples, n_features).astype(np.float32)
    
    # Create synthetic labels
    labels = ['benign', 'malware', 'ddos', 'port_scan', 'intrusion']
    y_synthetic = np.random.choice(labels, size=n_samples)
    
    # Convert to format expected by label encoder
    y_encoded = classifier.label_encoder.fit_transform(y_synthetic)
    
    try:
        # Train model with synthetic data
        print("Training model with synthetic data...")
        result = classifier.train_model(X_synthetic, y_encoded, test_size=0.2)
        print(f"Training completed successfully!")
        print(f"Train accuracy: {result['train_accuracy']:.4f}")
        print(f"Test accuracy: {result['test_accuracy']:.4f}")
        
        # Test prediction with sample packet
        sample_packet = {
            'packet_size': 1500,
            'protocol': 6,  # TCP
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
            'flow_iat_min': 50,
            'fwd_iat_total': 500,
            'fwd_iat_mean': 50,
            'fwd_iat_std': 25,
            'fwd_iat_max': 100,
            'fwd_iat_min': 25,
            'bwd_iat_total': 400,
            'bwd_iat_mean': 50,
            'bwd_iat_std': 25,
            'bwd_iat_max': 100,
            'bwd_iat_min': 25,
            'fwd_psh_flags': 0,
            'bwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            'fwd_header_length': 20,
            'bwd_header_length': 20,
            'fwd_packets_per_second': 10,
            'bwd_packets_per_second': 8,
            'min_packet_length': 60,
            'max_packet_length': 1500,
            'packet_length_mean': 1500,
            'packet_length_std': 100,
            'packet_length_variance': 10000,
            'down_up_ratio': 0.8,
            'average_packet_size': 1500,
            'avg_fwd_segment_size': 1500,
            'avg_bwd_segment_size': 1500,
            'subflow_fwd_packets': 10,
            'subflow_fwd_bytes': 15000,
            'subflow_bwd_packets': 8,
            'subflow_bwd_bytes': 12000,
            'init_win_bytes_forward': 65535,
            'init_win_bytes_backward': 65535,
            'act_data_pkt_fwd': 10,
            'min_seg_size_forward': 60,
            'active_mean': 100,
            'active_std': 50,
            'active_max': 200,
            'active_min': 50,
            'idle_mean': 100,
            'idle_std': 50,
            'idle_max': 200,
            'idle_min': 50
        }
        
        # Test prediction
        print("\nTesting prediction...")
        prediction = classifier.predict_threat(sample_packet)
        print(f"Prediction result: {prediction}")
        
        # Test model saving/loading
        print("\nTesting model save/load...")
        model_path = "threat_model.joblib"
        classifier.save_model(model_path)
        
        # Create new classifier and load model
        new_classifier = ThreatClassifier()
        new_classifier.load_model(model_path)
        
        # Test loaded model
        prediction2 = new_classifier.predict_threat(sample_packet)
        print(f"Loaded model prediction: {prediction2}")
        
        print("\nAll tests completed successfully!")
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
    
    # For actual usage with real data:
    print("\n" + "="*50)
    print("FOR REAL USAGE:")
    print("="*50)
    print("1. Prepare your CSV dataset with features and labels")
    print("2. Use prepare_training_data() to load and clean data")
    print("3. Use train_model() to train the classifier")
    print("4. Use save_model() to save the trained model")
    print("5. Use load_model() to load model for inference")
    print("6. Use predict_threat() for real-time classification")
    
    print("\nExample with real dataset:")
    print("classifier = ThreatClassifier()")
    print("X, y = classifier.prepare_training_data('your_dataset.csv')")
    print("classifier.train_model(X, y)")
    print("classifier.save_model('trained_model.joblib')")
    print("prediction = classifier.predict_threat(packet_data)")
    
    print("\nFeatures extracted from sample packet:", len(classifier.extract_features(sample_packet)))